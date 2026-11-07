"""JavaScript Analysis engine for RRI.

Performs deep passive analysis of JavaScript files to extract:
  - API paths (REST, GraphQL, etc.)
  - Internal application routes (SPA route definitions)
  - Full URLs (same-origin and cross-origin)
  - Source map references (//# sourceMappingURL=)
  - Configuration references (keys, tokens, endpoints in config objects)

All extraction is passive — no endpoint is probed.  Every JS file is
fetched via the HTTPEngine and checked against scope before and after
fetch.  External JS files are limited by max_script_files.

Results use the unified data model (make_js_analysis) and every
discovered path/url is tagged with a verification_status of
"discovered".
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlsplit

from core.models import (
    make_js_analysis,
    make_module_result,
)


class JSAnalyzer:
    """Analyzes JavaScript content for recon-relevant patterns."""

    MAX_SCRIPT_SIZE = 512 * 1024

    API_PATH_PATTERN = re.compile(
        r"""
        ["'`]
        (?P<path>
            /(?:api|rest|graphql|gql)(?:/v[0-9]+)?
            (?:/[a-zA-Z0-9_.~:@%{}\-]+)*
        )
        ["'`]
        """,
        re.VERBOSE | re.IGNORECASE,
    )

    ROUTE_PATTERN = re.compile(
        r"""
        (?:
            (?:path|route|to|href|url)\s*:\s*
            ["'`]
            (?P<route>
                /(?:[a-zA-Z0-9_.~:@%\-]+/)*[a-zA-Z0-9_.~:@%\-]*
            )
            ["'`]
        )
        """,
        re.VERBOSE | re.IGNORECASE,
    )

    URL_PATTERN = re.compile(
        r"""
        ["'`]
        (?P<url>
            https?://
            [a-zA-Z0-9\-]+
            (?:\.[a-zA-Z0-9\-]+)+
            (?:/[a-zA-Z0-9_.~:@%{}\-/]*)?
        )
        ["'`]
        """,
        re.VERBOSE | re.IGNORECASE,
    )

    SOURCE_MAP_PATTERN = re.compile(
        r"//[#@]\s*sourceMappingURL\s*=\s*(?P<ref>[^\s\n]+)",
        re.IGNORECASE,
    )

    CONFIG_KEY_PATTERN = re.compile(
        r"""
        (?:
            (?P<key>api_?key|apikey|secret|token|password|passwd|auth)
            \s*[:=]\s*
            ["'`]
            (?P<value>[^"'`]{3,200})
            ["'`]
        )
        """,
        re.VERBOSE | re.IGNORECASE,
    )

    SENSITIVE_KEY_TERMS = frozenset({
        "api_key", "apikey", "secret", "token",
        "password", "passwd", "auth",
    })

    def __init__(self, engine, max_script_files: int = 10):
        if (
            isinstance(max_script_files, bool)
            or not isinstance(max_script_files, int)
            or not 0 <= max_script_files <= 50
        ):
            raise ValueError("max_script_files must be between 0 and 50")

        self.engine = engine
        self.max_script_files = max_script_files

    @staticmethod
    def _decode_body(body: Any) -> str:
        if isinstance(body, bytes):
            return body.decode("utf-8", errors="replace")
        if isinstance(body, str):
            return body
        return ""

    def _resolve_script_url(self, base_url: str, reference: str) -> str | None:
        if not isinstance(reference, str) or not reference:
            return None

        reference = reference.strip()

        if not reference or len(reference) > 2048:
            return None

        if any(ord(c) < 32 for c in reference):
            return None

        try:
            resolved = urljoin(base_url, reference)
            parsed = urlsplit(resolved)

            if parsed.scheme not in ("http", "https"):
                return None

            if parsed.username or parsed.password:
                return None

            if parsed.fragment:
                resolved = resolved.split("#", 1)[0]

            allowed, _ = self.engine.scope.check(resolved)
            if not allowed:
                return None

            return resolved

        except (ValueError, TypeError, AttributeError):
            return None

    def _extract_api_paths(self, content: str) -> list[str]:
        results: list[str] = []
        seen: set[str] = set()

        for match in self.API_PATH_PATTERN.finditer(content):
            path = match.group("path")
            if path and path not in seen:
                seen.add(path)
                results.append(path)

        return results

    def _extract_routes(self, content: str) -> list[str]:
        results: list[str] = []
        seen: set[str] = set()

        for match in self.ROUTE_PATTERN.finditer(content):
            route = match.group("route")
            if route and route not in seen:
                seen.add(route)
                results.append(route)

        return results

    def _extract_urls(self, content: str) -> list[str]:
        results: list[str] = []
        seen: set[str] = set()

        for match in self.URL_PATTERN.finditer(content):
            url = match.group("url")
            if url and url not in seen:
                seen.add(url)
                results.append(url)

        return results

    def _extract_source_map_refs(self, content: str) -> list[str]:
        results: list[str] = []
        seen: set[str] = set()

        for match in self.SOURCE_MAP_PATTERN.finditer(content):
            ref = match.group("ref")
            if ref and ref not in seen:
                seen.add(ref)
                results.append(ref)

        return results

    def _extract_config_refs(self, content: str) -> list[str]:
        results: list[str] = []
        seen: set[str] = set()

        for match in self.CONFIG_KEY_PATTERN.finditer(content):
            key = match.group("key")
            if not key:
                continue
            key_lower = key.lower().replace(" ", "")
            if key_lower in self.SENSITIVE_KEY_TERMS:
                display = f"{key_lower}=[REDACTED]"
            else:
                display = f"{key_lower}=[REDACTED]"
            if display not in seen:
                seen.add(display)
                results.append(display)

        return results

    def _analyze_content(self, content: str, script_url: str, source: str) -> dict:
        return make_js_analysis(
            script_url=script_url,
            source=source,
            api_paths=self._extract_api_paths(content),
            internal_routes=self._extract_routes(content),
            urls=self._extract_urls(content),
            source_map_refs=self._extract_source_map_refs(content),
            config_refs=self._extract_config_refs(content),
        )

    async def scan(
        self,
        target: str,
        response: dict | None = None,
    ) -> dict:
        """Analyze JavaScript files referenced from the target page.

        Args:
            target: the seed URL
            response: pre-fetched response (if None, will fetch)

        Returns:
            Module result with analyzed_scripts, all_api_paths,
            all_routes, all_urls, all_source_map_refs, all_config_refs.
        """
        if not isinstance(target, str) or not target:
            return make_module_result(
                "js_analysis", status="error", target="",
                error="Target URL is required",
            )

        if response is None:
            try:
                response = await self.engine.fetch(target)
            except Exception as e:
                return make_module_result(
                    "js_analysis", status="error", target=target,
                    error=str(e),
                )

        if not isinstance(response, dict):
            return make_module_result(
                "js_analysis", status="error", target=target,
                error="Invalid response",
            )

        if response.get("status") != "completed":
            return make_module_result(
                "js_analysis",
                status=response.get("status", "error"),
                target=target,
                error=response.get("error", "Fetch failed"),
            )

        page_url = response.get("url", target)
        allowed, reason = self.engine.scope.check(page_url)

        if not allowed:
            return make_module_result(
                "js_analysis", status="blocked", target=target,
                error=f"Page URL outside scope: {reason}",
            )

        html_content = self._decode_body(response.get("body", b""))

        from modules.api_discovery import APIPageParser

        parser = APIPageParser()
        try:
            parser.feed(html_content)
            parser.close()
        except Exception:
            pass

        analyzed_scripts: list[dict] = []

        all_api_paths: set[str] = set()
        all_routes: set[str] = set()
        all_urls: set[str] = set()
        all_source_map_refs: set[str] = set()
        all_config_refs: set[str] = set()

        for inline_script in parser.inline_scripts:
            if not isinstance(inline_script, str) or not inline_script.strip():
                continue

            result = self._analyze_content(inline_script, page_url, "inline_javascript")
            analyzed_scripts.append(result)

            all_api_paths.update(result["api_paths"])
            all_routes.update(result["internal_routes"])
            all_urls.update(result["urls"])
            all_source_map_refs.update(result["source_map_refs"])
            all_config_refs.update(result["config_refs"])

        script_urls: list[str] = []
        seen_scripts: set[str] = set()

        for ref in parser.scripts:
            if len(script_urls) >= self.max_script_files:
                break

            resolved = self._resolve_script_url(page_url, ref)
            if resolved and resolved not in seen_scripts:
                seen_scripts.add(resolved)
                script_urls.append(resolved)

        fetched_count = 0
        skipped_count = 0

        for script_url in script_urls:
            allowed, _ = self.engine.scope.check(script_url)
            if not allowed:
                skipped_count += 1
                continue

            try:
                script_response = await self.engine.fetch(script_url)
            except Exception:
                skipped_count += 1
                analyzed_scripts.append(
                    make_js_analysis(
                        script_url=script_url,
                        source="external_javascript",
                        error="Fetch exception",
                    )
                )
                continue

            if script_response.get("status") != "completed":
                skipped_count += 1
                analyzed_scripts.append(
                    make_js_analysis(
                        script_url=script_url,
                        source="external_javascript",
                        error=script_response.get("error", "Fetch failed"),
                    )
                )
                continue

            actual_url = script_response.get("url", script_url)
            actual_allowed, _ = self.engine.scope.check(actual_url)
            if not actual_allowed:
                skipped_count += 1
                continue

            script_content = self._decode_body(
                script_response.get("body", b"")
            )

            if len(script_content) > self.MAX_SCRIPT_SIZE:
                script_content = script_content[: self.MAX_SCRIPT_SIZE]

            fetched_count += 1

            result = self._analyze_content(script_content, actual_url, "external_javascript")
            analyzed_scripts.append(result)

            all_api_paths.update(result["api_paths"])
            all_routes.update(result["internal_routes"])
            all_urls.update(result["urls"])
            all_source_map_refs.update(result["source_map_refs"])
            all_config_refs.update(result["config_refs"])

        return make_module_result(
            "js_analysis",
            target=page_url,
            analyzed_scripts=analyzed_scripts,
            all_api_paths=sorted(all_api_paths),
            all_routes=sorted(all_routes),
            all_urls=sorted(all_urls),
            all_source_map_refs=sorted(all_source_map_refs),
            all_config_refs=sorted(all_config_refs),
            script_files_discovered=len(script_urls),
            script_files_fetched=fetched_count,
            script_files_skipped=skipped_count,
            inline_scripts_analyzed=len(parser.inline_scripts),
            total_api_paths=len(all_api_paths),
            total_routes=len(all_routes),
            total_urls=len(all_urls),
            total_source_map_refs=len(all_source_map_refs),
            total_config_refs=len(all_config_refs),
        )
