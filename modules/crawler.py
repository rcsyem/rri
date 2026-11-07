"""Website crawler for RRI.

Collects internal links from HTML pages within the authorized scope.
Respects Scope Engine on every transition.  Does not follow
subdomains, external links, or non-HTTP(S) schemes.

Limits:
  - max_depth: maximum crawl depth from the seed URL
  - max_pages: maximum number of pages to fetch
  - timeout: per-request timeout (inherited from HTTPEngine)
  - circular link detection via a visited set

Every discovered URL is tagged with a verification_status:
  - ``tested``    -- a request was made
  - ``confirmed`` -- the request returned a 2xx status
  - ``failed``    -- the request returned an error or non-2xx status
  - ``discovered``-- the URL was found in content but not yet fetched
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

from core.models import make_discovered_url, make_module_result


class LinkExtractor(HTMLParser):
    """Extracts href/src references from HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attr = None

        if tag == "a":
            attr = "href"
        elif tag == "link":
            attr = "href"
        elif tag == "script":
            attr = "src"
        elif tag == "img":
            attr = "src"
        elif tag == "iframe":
            attr = "src"
        elif tag == "form":
            attr = "action"

        if attr is None:
            return

        value = dict(attrs).get(attr)

        if isinstance(value, str) and value.strip():
            self.links.append(value.strip())


class Crawler:
    """Crawls internal pages within the authorized scope."""

    MAX_DEPTH = 3
    MAX_PAGES = 20

    SKIP_EXTENSIONS = re.compile(
        r"\.(?:jpg|jpeg|png|gif|svg|webp|ico|css|js|woff2?|ttf|eot|otf|"
        r"pdf|zip|tar|gz|7z|rar|mp[34]|wav|avi|mov|mp4|webm|docx?|xlsx?|pptx?)"
        r"(?:$|[?#])",
        re.I,
    )

    def __init__(
        self,
        engine,
        max_depth: int = MAX_DEPTH,
        max_pages: int = MAX_PAGES,
    ):
        if (
            isinstance(max_depth, bool)
            or not isinstance(max_depth, int)
            or max_depth < 1
        ):
            raise ValueError("max_depth must be a positive integer")

        if (
            isinstance(max_pages, bool)
            or not isinstance(max_pages, int)
            or max_pages < 1
        ):
            raise ValueError("max_pages must be a positive integer")

        self.engine = engine
        self.max_depth = max_depth
        self.max_pages = max_pages

    def _resolve(self, base_url: str, reference: str) -> str | None:
        if not isinstance(reference, str) or not reference:
            return None

        reference = reference.strip()

        if not reference or len(reference) > 2048:
            return None

        if any(ord(c) < 32 for c in reference):
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

            if parsed.fragment:
                resolved = resolved.split("#", 1)[0]

            allowed, _ = self.engine.scope.check(resolved)
            if not allowed:
                return None

            return resolved

        except (ValueError, TypeError, AttributeError):
            return None

    def _should_skip(self, url: str) -> bool:
        return bool(self.SKIP_EXTENSIONS.search(url))

    @staticmethod
    def _decode_body(body: Any) -> str:
        if isinstance(body, bytes):
            return body.decode("utf-8", errors="replace")
        if isinstance(body, str):
            return body
        return ""

    async def crawl(self, seed_url: str) -> dict:
        if not isinstance(seed_url, str) or not seed_url:
            return make_module_result(
                "crawler", status="error", target="",
                error="Seed URL is required",
            )

        allowed, reason = self.engine.scope.check(seed_url)
        if not allowed:
            return make_module_result(
                "crawler", status="blocked", target=seed_url,
                error=f"Seed URL outside scope: {reason}",
            )

        from core.models import make_discovered_path

        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(seed_url, 0)]

        discovered_urls: list[dict] = []
        discovered_paths: list[dict] = []
        url_to_path: dict[str, dict] = {}
        pages_fetched = 0
        pages_failed = 0

        while queue and pages_fetched < self.max_pages:
            current_url, depth = queue.pop(0)

            if current_url in visited:
                continue

            visited.add(current_url)

            if depth > self.max_depth:
                continue

            if self._should_skip(current_url):
                continue

            try:
                response = await self.engine.fetch(current_url)
            except Exception:
                pages_failed += 1
                discovered_urls.append(
                    make_discovered_url(
                        current_url, "crawler",
                        verification="failed", error="Fetch exception",
                    )
                )
                continue

            status = response.get("status")

            if status != "completed":
                pages_failed += 1
                discovered_urls.append(
                    make_discovered_url(
                        current_url, "crawler",
                        verification="failed",
                        error=response.get("error", "Fetch failed"),
                    )
                )
                continue

            actual_url = response.get("url", current_url)
            http_status = response.get("http_status")

            actual_allowed, _ = self.engine.scope.check(actual_url)
            if not actual_allowed:
                pages_failed += 1
                continue

            pages_fetched += 1

            confirmed = isinstance(http_status, int) and 200 <= http_status < 300

            url_entry = make_discovered_url(
                actual_url, "crawler",
                verification="confirmed" if confirmed else "tested",
                http_status=http_status,
                content_type=response.get("headers", {}).get("Content-Type"),
            )
            discovered_urls.append(url_entry)

            try:
                path = urlsplit(actual_url).path or "/"
                path_entry = make_discovered_path(
                    path, "crawler",
                    verification="confirmed" if confirmed else "tested",
                    http_status=http_status,
                )
                if path not in url_to_path:
                    url_to_path[path] = path_entry
                    discovered_paths.append(path_entry)
            except (ValueError, TypeError):
                pass

            if depth >= self.max_depth:
                continue

            body = self._decode_body(response.get("body", b""))
            parser = LinkExtractor()

            try:
                parser.feed(body)
                parser.close()
            except Exception:
                pass

            for link in parser.links:
                resolved = self._resolve(actual_url, link)

                if resolved is None:
                    continue

                if resolved in visited:
                    continue

                if resolved not in {u["url"] for u in discovered_urls}:
                    discovered_urls.append(
                        make_discovered_url(resolved, "crawler", verification="discovered")
                    )

                    try:
                        link_path = urlsplit(resolved).path or "/"
                        if link_path not in url_to_path:
                            path_entry = make_discovered_path(link_path, "crawler")
                            url_to_path[link_path] = path_entry
                            discovered_paths.append(path_entry)
                    except (ValueError, TypeError):
                        pass

                if not self._should_skip(resolved):
                    queue.append((resolved, depth + 1))

        seen_urls: set[str] = set()
        unique_urls: list[dict] = []
        for item in discovered_urls:
            if item["url"] not in seen_urls:
                seen_urls.add(item["url"])
                unique_urls.append(item)

        seen_paths: set[str] = set()
        unique_paths: list[dict] = []
        for item in discovered_paths:
            if item["path"] not in seen_paths:
                seen_paths.add(item["path"])
                unique_paths.append(item)

        return make_module_result(
            "crawler",
            target=seed_url,
            discovered_urls=unique_urls,
            discovered_paths=unique_paths,
            pages_fetched=pages_fetched,
            pages_failed=pages_failed,
            unique_url_count=len(unique_urls),
            unique_path_count=len(unique_paths),
        )
