import re

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit


class APIPageParser(HTMLParser):

    def __init__(self):
        super().__init__(convert_charrefs=True)

        self.scripts = []
        self.links = []
        self.inline_scripts = []

        self._inside_script = False
        self._script_data = []

    def handle_starttag(self, tag, attrs):

        attrs = dict(attrs)

        if tag.lower() == "script":

            src = attrs.get("src")

            if src:
                self.scripts.append(src)

            self._inside_script = True
            self._script_data = []

        elif tag.lower() in ("a", "link"):

            href = attrs.get("href")

            if href:
                self.links.append(href)

    def handle_data(self, data):

        if self._inside_script:
            self._script_data.append(data)

    def handle_endtag(self, tag):

        if tag.lower() == "script":

            content = "".join(self._script_data)

            if content.strip():
                self.inline_scripts.append(content)

            self._inside_script = False
            self._script_data = []


class APIDiscovery:

    MAX_SCRIPT_FILES = 10
    MAX_SCRIPT_URL_LENGTH = 2048
    MAX_ENDPOINTS = 300
    MAX_SOURCE_LENGTH = 500

    API_PATH_PATTERN = re.compile(
        r"""
        (?P<quote>["'`])
        (?P<path>
            (?:
                /api(?:/v[0-9]+)?(?:/[a-zA-Z0-9_.~:@%{}-]+)*
                |
                /rest(?:/[a-zA-Z0-9_.~:@%{}-]+)*
                |
                /graphql(?:/[a-zA-Z0-9_.~-]+)*
                |
                /gql(?:/[a-zA-Z0-9_.~-]+)*
                |
                /v[0-9]+(?:/[a-zA-Z0-9_.~:@%{}-]+)+
            )
        )
        (?P=quote)
        """,
        re.I | re.X
    )

    OPENAPI_PATTERN = re.compile(
        r"""["'`]([^"'`]{1,500}(?:openapi|swagger)
        (?:\.json|\.ya?ml)?(?:\?[^"'`]*)?)["'`]""",
        re.I | re.X
    )

    GRAPHQL_PATTERN = re.compile(
        r"""
        (?:
            \bgraphql\b
            |
            \bGraphQLClient\b
            |
            \bApolloClient\b
            |
            \burql\b
        )
        """,
        re.I | re.X
    )

    def __init__(
        self,
        engine,
        max_script_files=MAX_SCRIPT_FILES
    ):

        if (
            isinstance(max_script_files, bool)
            or not isinstance(max_script_files, int)
            or not 0 <= max_script_files <= 50
        ):
            raise ValueError(
                "max_script_files must be between 0 and 50"
            )

        self.engine = engine
        self.max_script_files = max_script_files

    @staticmethod
    def _decode_body(body):

        if isinstance(body, bytes):
            return body.decode("utf-8", errors="replace")

        if isinstance(body, str):
            return body

        return ""

    @staticmethod
    def _confidence(score):

        if score >= 85:
            return "high"

        if score >= 60:
            return "medium"

        return "low"

    def _authorized_url(self, base_url, reference):

        if not isinstance(reference, str):
            return None

        reference = reference.strip()

        if (
            not reference
            or len(reference) > self.MAX_SCRIPT_URL_LENGTH
            or any(ord(char) < 32 for char in reference)
        ):
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

    def _add(
        self,
        findings,
        url,
        category,
        source,
        evidence,
        score
    ):

        if len(findings) >= self.MAX_ENDPOINTS:
            if url not in findings:
                return

        item = findings.setdefault(
            url,
            {
                "url": url,
                "category": category,
                "score": 0,
                "confidence": None,
                "sources": [],
                "evidence": []
            }
        )

        item["score"] = min(
            100,
            item["score"] + score
        )

        if source not in item["sources"]:
            item["sources"].append(source)

        evidence_item = {
            "source": source,
            "value": str(evidence)[:self.MAX_SOURCE_LENGTH]
        }

        if evidence_item not in item["evidence"]:
            item["evidence"].append(evidence_item)

    def _extract_endpoints(
        self,
        content,
        base_url,
        source,
        findings
    ):

        for match in self.API_PATH_PATTERN.finditer(content):

            path = match.group("path")

            resolved = self._authorized_url(
                base_url,
                path
            )

            if not resolved:
                continue

            lowered = path.lower()

            if "graphql" in lowered or "/gql" in lowered:
                category = "GraphQL"
                score = 95
            else:
                category = "REST"
                score = 85

            self._add(
                findings,
                resolved,
                category,
                source,
                match.group(0),
                score
            )

            if len(findings) >= self.MAX_ENDPOINTS:
                return

    def _extract_openapi(
        self,
        content,
        base_url,
        source,
        findings
    ):

        for match in self.OPENAPI_PATTERN.finditer(content):

            reference = match.group(1)

            resolved = self._authorized_url(
                base_url,
                reference
            )

            if not resolved:
                continue

            self._add(
                findings,
                resolved,
                "API Documentation",
                source,
                match.group(0),
                90
            )

    def _extract_graphql_indicators(
        self,
        content,
        base_url,
        source,
        findings
    ):

        if not self.GRAPHQL_PATTERN.search(content):
            return

        candidates = (
            "/graphql",
            "/api/graphql",
            "/gql"
        )

        for path in candidates:

            resolved = self._authorized_url(
                base_url,
                path
            )

            if not resolved:
                continue

            self._add(
                findings,
                resolved,
                "GraphQL Candidate",
                source,
                "GraphQL client/library indicator",
                55
            )

    async def scan(self, target, response=None):

        if response is None:

            response = await self.engine.fetch(target)

        if not isinstance(response, dict):
            return self._error(
                target,
                "Invalid HTTP response"
            )

        if response.get("status") != "completed":
            return self._error(
                target,
                response.get("error") or "Page fetch failed",
                response.get("status", "error")
            )

        page_url = response.get("url", target)

        allowed, reason = self.engine.scope.check(page_url)

        if not allowed:
            return self._error(
                target,
                f"Page URL outside scope: {reason}",
                "blocked"
            )

        findings = {}

        html = self._decode_body(
            response.get("body", b"")
        )

        parser = APIPageParser()

        try:
            parser.feed(html)
            parser.close()
        except Exception:
            pass

        # Main HTML
        self._extract_endpoints(
            html,
            page_url,
            "html",
            findings
        )

        self._extract_openapi(
            html,
            page_url,
            "html",
            findings
        )

        self._extract_graphql_indicators(
            html,
            page_url,
            "html",
            findings
        )

        # Inline JavaScript
        for script in parser.inline_scripts:

            self._extract_endpoints(
                script,
                page_url,
                "inline_javascript",
                findings
            )

            self._extract_openapi(
                script,
                page_url,
                "inline_javascript",
                findings
            )

            self._extract_graphql_indicators(
                script,
                page_url,
                "inline_javascript",
                findings
            )

        # External JavaScript
        script_urls = []
        seen_scripts = set()

        for reference in parser.scripts:

            if len(script_urls) >= self.max_script_files:
                break

            resolved = self._authorized_url(
                page_url,
                reference
            )

            if not resolved or resolved in seen_scripts:
                continue

            seen_scripts.add(resolved)
            script_urls.append(resolved)

            if len(script_urls) >= self.max_script_files:
                break

        fetched_scripts = 0
        skipped_scripts = 0

        for script_url in script_urls:

            # Scope is checked again immediately before fetching.
            allowed, _ = self.engine.scope.check(script_url)

            if not allowed:
                skipped_scripts += 1
                continue

            try:
                script_response = await self.engine.fetch(
                    script_url
                )
            except Exception:
                skipped_scripts += 1
                continue

            if script_response.get("status") != "completed":
                skipped_scripts += 1
                continue

            actual_url = script_response.get(
                "url",
                script_url
            )

            actual_allowed, _ = self.engine.scope.check(
                actual_url
            )

            if not actual_allowed:
                skipped_scripts += 1
                continue

            script_content = self._decode_body(
                script_response.get("body", b"")
            )

            fetched_scripts += 1

            self._extract_endpoints(
                script_content,
                actual_url,
                "external_javascript",
                findings
            )

            self._extract_openapi(
                script_content,
                actual_url,
                "external_javascript",
                findings
            )

            self._extract_graphql_indicators(
                script_content,
                actual_url,
                "external_javascript",
                findings
            )

        results = list(findings.values())

        for item in results:

            item["confidence"] = self._confidence(
                item["score"]
            )

        results.sort(
            key=lambda item: (
                -item["score"],
                item["url"]
            )
        )

        return {
            "status": "completed",
            "target": page_url,
            "endpoints": results,
            "endpoint_count": len(results),
            "script_files_discovered": len(script_urls),
            "script_files_fetched": fetched_scripts,
            "script_files_skipped": skipped_scripts,
            "error": None
        }

    @staticmethod
    def _error(target, message, status="error"):

        return {
            "status": status,
            "target": target,
            "endpoints": [],
            "endpoint_count": 0,
            "script_files_discovered": 0,
            "script_files_fetched": 0,
            "script_files_skipped": 0,
            "error": message
        }
