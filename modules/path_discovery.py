"""Path Discovery engine for RRI.

Discovers paths on the target domain from multiple passive sources:
  - HTML href/src/action attributes
  - Inline JavaScript strings
  - External JavaScript files (fetched via HTTPEngine)
  - Internal links found during crawling

Every discovered path is tagged with:
  - discovery_source: where the path was found
  - verification_status: discovered / tested / confirmed / failed

Optional wordlist-based discovery can be enabled explicitly but is
disabled by default.  When enabled, it sends GET requests to paths
from a provided list and records the result.

This module NEVER sends requests to API endpoints.  Wordlist testing
is limited to path existence checks (GET) and respects all scope and
safety controls.
"""

from __future__ import annotations

import asyncio
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

from core.models import (
    make_discovered_path,
    make_module_result,
)


class PathExtractor(HTMLParser):
    """Extracts path-like references from HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.references: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        for attr in ("href", "src", "action", "data-url", "data-src"):
            value = attrs_dict.get(attr)
            if isinstance(value, str) and value.strip():
                self.references.append(value.strip())


class PathDiscovery:
    """Discovers paths on the target domain from passive sources."""

    PATH_PATTERN = re.compile(
        r"""
        (?:
            ["'`]\s*
            (?P<path>
                /(?:[a-zA-Z0-9_.~:@%\-]+/)*[a-zA-Z0-9_.~:@%\-]*
            )
            \s*["'`]
        )
        """,
        re.VERBOSE,
    )

    MIN_PATH_LENGTH = 2
    MAX_PATHS = 500
    MAX_SCRIPT_FILES = 10
    MAX_SCRIPT_SIZE = 512 * 1024
    DEFAULT_WORDLIST_DELAY = 0.5
    MAX_WORDLIST_DELAY = 10.0
    MAX_WORDLIST_TESTS = 100

    def __init__(
        self,
        engine,
        max_script_files: int = MAX_SCRIPT_FILES,
        wordlist_delay: float = DEFAULT_WORDLIST_DELAY,
    ):
        if (
            isinstance(max_script_files, bool)
            or not isinstance(max_script_files, int)
            or not 0 <= max_script_files <= 50
        ):
            raise ValueError("max_script_files must be between 0 and 50")

        if (
            isinstance(wordlist_delay, bool)
            or not isinstance(wordlist_delay, (int, float))
            or wordlist_delay < 0
            or wordlist_delay > self.MAX_WORDLIST_DELAY
        ):
            raise ValueError(
                f"wordlist_delay must be between 0 and {self.MAX_WORDLIST_DELAY}"
            )

        self.engine = engine
        self.max_script_files = max_script_files
        self.wordlist_delay = float(wordlist_delay)

    @staticmethod
    def _decode_body(body: Any) -> str:
        if isinstance(body, bytes):
            return body.decode("utf-8", errors="replace")
        if isinstance(body, str):
            return body
        return ""

    def _resolve_to_path(self, base_url: str, reference: str) -> str | None:
        if not isinstance(reference, str) or not reference:
            return None

        reference = reference.strip()

        if (
            not reference
            or len(reference) > 2048
            or any(ord(c) < 32 for c in reference)
        ):
            return None

        if reference.startswith(("#", "mailto:", "javascript:", "data:", "tel:")):
            return None

        try:
            resolved = urljoin(base_url, reference)
            parsed = urlsplit(resolved)

            if parsed.scheme not in ("http", "https"):
                return None

            if parsed.username or parsed.password:
                return None

            allowed, _ = self.engine.scope.check(resolved)
            if not allowed:
                return None

            return parsed.path or "/"

        except (ValueError, TypeError, AttributeError):
            return None

    def _add_path(
        self,
        path: str,
        source: str,
        paths: dict[str, dict],
        verification: str = "discovered",
        http_status: int | None = None,
        error: str | None = None,
    ):
        if path is None or path == "":
            return

        if len(paths) >= self.MAX_PATHS:
            return

        if path not in paths:
            paths[path] = make_discovered_path(
                path, source,
                verification=verification,
                http_status=http_status,
                error=error,
            )

    def _extract_from_html(self, html_content: str, base_url: str, paths: dict):
        parser = PathExtractor()

        try:
            parser.feed(html_content)
            parser.close()
        except Exception:
            pass

        for ref in parser.references:
            path = self._resolve_to_path(base_url, ref)
            if path:
                self._add_path(path, "html", paths)

    def _extract_from_javascript(self, content: str, base_url: str, source: str, paths: dict):
        for match in self.PATH_PATTERN.finditer(content):
            path = match.group("path")

            if not path or len(path) < self.MIN_PATH_LENGTH:
                continue

            full_url = urljoin(base_url, path)
            allowed, _ = self.engine.scope.check(full_url)

            if not allowed:
                continue

            self._add_path(path, source, paths)

    async def scan(
        self,
        target: str,
        response: dict | None = None,
        crawl_results: dict | None = None,
        wordlist: list[str] | None = None,
    ) -> dict:
        if not isinstance(target, str) or not target:
            return make_module_result(
                "path_discovery", status="error", target="",
                error="Target URL is required",
            )

        if response is None:
            try:
                response = await self.engine.fetch(target)
            except Exception as e:
                return make_module_result(
                    "path_discovery", status="error", target=target,
                    error=str(e),
                )

        if not isinstance(response, dict):
            return make_module_result(
                "path_discovery", status="error", target=target,
                error="Invalid response",
            )

        if response.get("status") != "completed":
            return make_module_result(
                "path_discovery",
                status=response.get("status", "error"),
                target=target,
                error=response.get("error", "Fetch failed"),
            )

        page_url = response.get("url", target)
        allowed, reason = self.engine.scope.check(page_url)

        if not allowed:
            return make_module_result(
                "path_discovery", status="blocked", target=target,
                error=f"Page URL outside scope: {reason}",
            )

        paths: dict[str, dict] = {}

        html_content = self._decode_body(response.get("body", b""))
        self._extract_from_html(html_content, page_url, paths)

        from modules.api_discovery import APIPageParser

        api_parser = APIPageParser()
        try:
            api_parser.feed(html_content)
            api_parser.close()
        except Exception:
            pass

        for script in api_parser.inline_scripts:
            self._extract_from_javascript(script, page_url, "inline_javascript", paths)

        script_urls = []
        seen_scripts: set[str] = set()

        for ref in api_parser.scripts:
            if len(script_urls) >= self.max_script_files:
                break

            if not isinstance(ref, str) or not ref:
                continue

            try:
                resolved = urljoin(page_url, ref)
                parsed = urlsplit(resolved)

                if parsed.scheme not in ("http", "https"):
                    continue
                if parsed.username or parsed.password:
                    continue
                if parsed.fragment:
                    resolved = resolved.split("#", 1)[0]

                allowed, _ = self.engine.scope.check(resolved)
                if not allowed:
                    continue

                if resolved not in seen_scripts:
                    seen_scripts.add(resolved)
                    script_urls.append(resolved)

            except (ValueError, TypeError, AttributeError):
                continue

        for script_url in script_urls:
            try:
                script_response = await self.engine.fetch(script_url)
            except Exception:
                continue

            if script_response.get("status") != "completed":
                continue

            actual_url = script_response.get("url", script_url)
            actual_allowed, _ = self.engine.scope.check(actual_url)
            if not actual_allowed:
                continue

            script_content = self._decode_body(
                script_response.get("body", b"")
            )

            if len(script_content) > self.MAX_SCRIPT_SIZE:
                script_content = script_content[: self.MAX_SCRIPT_SIZE]

            self._extract_from_javascript(script_content, actual_url, "external_javascript", paths)

        if crawl_results and isinstance(crawl_results, dict):
            crawl_paths = crawl_results.get("discovered_paths", [])
            if isinstance(crawl_paths, list):
                for p in crawl_paths:
                    if isinstance(p, dict):
                        path_str = p.get("path")
                        if isinstance(path_str, str) and path_str and path_str not in paths:
                            paths[path_str] = make_discovered_path(
                                path_str, "crawler",
                                verification=p.get("verification_status", "discovered"),
                                http_status=p.get("http_status"),
                            )

        tested_paths: list[dict] = []
        confirmed_paths: list[dict] = []
        failed_paths: list[dict] = []

        if wordlist is not None and isinstance(wordlist, list):
            for i, word in enumerate(wordlist):
                if not isinstance(word, str) or not word:
                    continue

                if not word.startswith("/"):
                    word = "/" + word

                test_url = urljoin(page_url, word)
                allowed, _ = self.engine.scope.check(test_url)
                if not allowed:
                    continue

                if len(tested_paths) >= self.MAX_WORDLIST_TESTS:
                    break

                if i > 0 and self.wordlist_delay > 0:
                    await asyncio.sleep(self.wordlist_delay)

                try:
                    test_response = await self.engine.fetch(test_url)
                except Exception:
                    failed_paths.append(
                        make_discovered_path(word, "wordlist", verification="failed", error="Fetch error")
                    )
                    continue

                test_status = test_response.get("status")
                http_status = test_response.get("http_status")

                if test_status == "completed" and isinstance(http_status, int) and 200 <= http_status < 300:
                    confirmed_paths.append(
                        make_discovered_path(word, "wordlist", verification="confirmed", http_status=http_status)
                    )
                    if word not in paths:
                        paths[word] = make_discovered_path(
                            word, "wordlist", verification="confirmed", http_status=http_status
                        )
                else:
                    failed_paths.append(
                        make_discovered_path(
                            word, "wordlist", verification="failed",
                            http_status=http_status,
                            error=test_response.get("error", "Non-2xx"),
                        )
                    )

                tested_paths.append(
                    make_discovered_path(word, "wordlist", verification="tested", http_status=http_status)
                )

        all_paths = list(paths.values())
        discovered_only = [p for p in all_paths if p["verification_status"] == "discovered"]

        return make_module_result(
            "path_discovery",
            target=page_url,
            discovered_paths=all_paths,
            discovered_only=discovered_only,
            tested_paths=tested_paths,
            confirmed_paths=confirmed_paths,
            failed_paths=failed_paths,
            path_count=len(all_paths),
            script_files_analyzed=len(script_urls),
            wordlist_enabled=wordlist is not None,
        )
