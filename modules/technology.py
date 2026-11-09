import asyncio
import re

from html.parser import HTMLParser

from core.http_engine import HTTPEngine


class PageAnalyzer(HTMLParser):

    def __init__(self):
        super().__init__(convert_charrefs=True)

        self.meta = {}
        self.scripts = []
        self.stylesheets = []
        self.inline_scripts = []
        self.tags = set()
        self.ids = set()
        self.classes = set()

        self._inside_script = False
        self._script_data = []

    def handle_starttag(self, tag, attrs):

        tag = tag.lower()
        self.tags.add(tag)

        attrs = dict(attrs)

        element_id = attrs.get("id")
        if element_id:
            self.ids.add(element_id.lower())

        class_value = attrs.get("class", "")
        if class_value:
            self.classes.update(
                item.lower()
                for item in class_value.split()
            )

        if tag == "meta":

            name = (
                attrs.get("name")
                or attrs.get("property")
                or ""
            ).lower()

            content = attrs.get("content", "")

            if name and content:
                self.meta[name] = content

        elif tag == "script":

            src = attrs.get("src")

            if src:
                self.scripts.append(src)

            self._inside_script = True
            self._script_data = []

        elif tag == "link":

            rel = attrs.get("rel", "").lower()
            href = attrs.get("href")

            if href and "stylesheet" in rel:
                self.stylesheets.append(href)

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


class TechnologyDetector:

    def __init__(self, engine=None):

        self.engine = engine or HTTPEngine()

    @staticmethod
    def _confidence(score):

        if score >= 80:
            return "high"

        if score >= 45:
            return "medium"

        return "low"

    @staticmethod
    def _header(headers, name):

        name = name.lower()

        for key, value in headers.items():

            if str(key).lower() == name:
                return str(value)

        return ""

    def _analyze(self, target, response):

        headers = response.get("headers") or {}

        body = response.get("body", b"")

        if isinstance(body, bytes):
            html = body.decode("utf-8", errors="replace")
        elif isinstance(body, str):
            html = body
        else:
            html = ""

        parser = PageAnalyzer()

        try:
            parser.feed(html)
            parser.close()
        except Exception:
            pass

        findings = {}

        def add(name, category, score, source, indicator, value):

            if not name or not value:
                return

            item = findings.setdefault(
                name,
                {
                    "name": name,
                    "category": category,
                    "score": 0,
                    "evidence": []
                }
            )

            item["score"] = min(
                100,
                item["score"] + score
            )

            evidence = {
                "source": source,
                "indicator": indicator,
                "value": str(value)[:500]
            }

            if evidence not in item["evidence"]:
                item["evidence"].append(evidence)

        # --------------------------------------------------
        # HTTP HEADERS
        # --------------------------------------------------

        server = self._header(headers, "server")

        server_rules = [
            (r"\bnginx\b", "Nginx", "Web Server", 85),
            (r"\bapache\b", "Apache", "Web Server", 85),
            (r"\blitespeed\b", "LiteSpeed", "Web Server", 85),
            (r"\bmicrosoft-iis\b", "Microsoft IIS", "Web Server", 85),
            (r"\bcaddy\b", "Caddy", "Web Server", 85),
            (r"\bcloudflare\b", "Cloudflare", "Infrastructure", 90),
        ]

        for pattern, name, category, score in server_rules:

            if re.search(pattern, server, re.I):
                add(
                    name, category, score,
                    "header", "Server", server
                )

        powered_by = self._header(
            headers,
            "x-powered-by"
        )

        backend_rules = [
            (r"\bphp\b", "PHP", "Backend", 85),
            (r"\bexpress\b", "Express", "Backend", 80),
            (r"\basp\.net\b", "ASP.NET", "Backend", 85),
            (r"\bnext\.js\b", "Next.js", "Framework", 85),
            (r"\bnuxt\b", "Nuxt", "Framework", 85),
        ]

        for pattern, name, category, score in backend_rules:

            if re.search(pattern, powered_by, re.I):
                add(
                    name, category, score,
                    "header", "X-Powered-By", powered_by
                )

        cloudflare_ray = self._header(headers, "cf-ray")

        if cloudflare_ray:
            add(
                "Cloudflare",
                "Infrastructure",
                95,
                "header",
                "CF-Ray",
                cloudflare_ray
            )

        via = self._header(headers, "via")

        if via:
            if re.search(r"cloudfront", via, re.I):
                add(
                    "Amazon CloudFront",
                    "CDN",
                    90,
                    "header",
                    "Via",
                    via
                )

        # --------------------------------------------------
        # COOKIES
        # --------------------------------------------------

        cookie_headers = []

        for key, value in headers.items():

            if str(key).lower() == "set-cookie":

                if isinstance(value, (list, tuple)):
                    cookie_headers.extend(value)
                else:
                    cookie_headers.append(value)

        cookie_rules = [
            (r"\bPHPSESSID=", "PHP", "Backend", 85),
            (r"\blaravel_session=", "Laravel", "Framework", 95),
            (r"\bwordpress_logged_in_", "WordPress", "CMS", 95),
            (r"\bwp-settings-", "WordPress", "CMS", 85),
            (r"\bcsrftoken=", "Django", "Framework", 70),
            (r"\bsessionid=", "Django", "Framework", 45),
            (r"\bconnect\.sid=", "Express", "Backend", 85),
            (r"\bASP\.NET_SessionId=", "ASP.NET", "Backend", 95),
            (r"\bJSESSIONID=", "Java", "Backend", 75),
        ]

        for cookie in cookie_headers:

            cookie = str(cookie)

            for pattern, name, category, score in cookie_rules:

                if re.search(pattern, cookie, re.I):
                    add(
                        name, category, score,
                        "cookie", pattern, cookie
                    )

        # --------------------------------------------------
        # HTML META TAGS
        # --------------------------------------------------

        generator = parser.meta.get("generator", "")

        generator_rules = [
            (r"wordpress", "WordPress", "CMS"),
            (r"drupal", "Drupal", "CMS"),
            (r"joomla", "Joomla", "CMS"),
            (r"wix", "Wix", "Platform"),
            (r"shopify", "Shopify", "Platform"),
            (r"next\.?js", "Next.js", "Framework"),
        ]

        for pattern, name, category in generator_rules:

            if re.search(pattern, generator, re.I):
                add(
                    name, category, 95,
                    "html_meta",
                    "generator",
                    generator
                )

        # --------------------------------------------------
        # HTML CONTENT
        # --------------------------------------------------

        html_rules = [
            (
                r"/wp-content/|/wp-includes/",
                "WordPress",
                "CMS",
                90
            ),
            (
                r"/sites/default/files/",
                "Drupal",
                "CMS",
                90
            ),
            (
                r"/media/system/js/",
                "Joomla",
                "CMS",
                85
            ),
            (
                r"__NEXT_DATA__|/_next/static/",
                "Next.js",
                "Framework",
                95
            ),
            (
                r"__NUXT__|/_nuxt/",
                "Nuxt",
                "Framework",
                95
            ),
            (
                r"data-reactroot|data-reactid",
                "React",
                "Frontend",
                75
            ),
            (
                r"ng-version=",
                "Angular",
                "Frontend",
                85
            ),
            (
                r"data-v-[a-f0-9]{6,}",
                "Vue.js",
                "Frontend",
                75
            ),
            (
                r"content=\".*?shopify",
                "Shopify",
                "Platform",
                70
            ),
        ]

        for pattern, name, category, score in html_rules:

            match = re.search(pattern, html, re.I)

            if match:
                add(
                    name, category, score,
                    "html",
                    pattern,
                    match.group(0)
                )

        # --------------------------------------------------
        # JAVASCRIPT AND CSS ASSET REFERENCES
        # --------------------------------------------------

        asset_urls = (
            parser.scripts
            + parser.stylesheets
        )

        asset_rules = [
            (
                r"jquery(?:[-.]|\.)?(?:min\.)?js",
                "jQuery",
                "Frontend",
                90
            ),
            (
                r"react(?:-dom)?(?:\.production)?(?:\.min)?\.js",
                "React",
                "Frontend",
                85
            ),
            (
                r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js",
                "Vue.js",
                "Frontend",
                85
            ),
            (
                r"angular(?:\.min)?\.js",
                "AngularJS",
                "Frontend",
                85
            ),
            (
                r"/_next/",
                "Next.js",
                "Framework",
                90
            ),
            (
                r"/_nuxt/",
                "Nuxt",
                "Framework",
                90
            ),
        ]

        for asset in asset_urls:

            for pattern, name, category, score in asset_rules:

                if re.search(pattern, asset, re.I):
                    add(
                        name, category, score,
                        "asset_reference",
                        pattern,
                        asset
                    )

        # --------------------------------------------------
        # INLINE JAVASCRIPT
        # --------------------------------------------------

        inline_text = "\n".join(parser.inline_scripts)

        inline_rules = [
            (
                r"window\.__NEXT_DATA__",
                "Next.js",
                "Framework",
                90
            ),
            (
                r"__VUE__|Vue\.createApp",
                "Vue.js",
                "Frontend",
                70
            ),
            (
                r"React\.createElement|ReactDOM\.createRoot",
                "React",
                "Frontend",
                70
            ),
        ]

        for pattern, name, category, score in inline_rules:

            if re.search(pattern, inline_text, re.I):
                add(
                    name, category, score,
                    "inline_javascript",
                    pattern,
                    pattern
                )

        technologies = []

        for item in findings.values():

            item["confidence"] = self._confidence(
                item["score"]
            )

            item["evidence_count"] = len(
                item["evidence"]
            )

            technologies.append(item)

        technologies.sort(
            key=lambda item: (
                -item["score"],
                item["name"].lower()
            )
        )

        return {
            "status": "completed",
            "target": response.get("url", target),
            "http_status": response.get("http_status"),
            "technologies": technologies,
            "technology_count": len(technologies),
            "error": None
        }

    async def scan(self, target, response=None):

        try:
            if response is None:
                response = await self.engine.fetch(target)

        except Exception as error:

            return {
                "status": "error",
                "target": target,
                "technologies": [],
                "technology_count": 0,
                "error": str(error)
            }

        if response.get("status") != "completed":

            return {
                "status": response.get("status", "error"),
                "target": target,
                "technologies": [],
                "technology_count": 0,
                "error": response.get("error")
            }

        actual_url = response.get("url", target)

        scope = getattr(self.engine, "scope", None) if self.engine else None
        if scope is None:
            return {
                "status": "blocked",
                "target": target,
                "technologies": [],
                "technology_count": 0,
                "error": "No scope engine available — cannot verify response URL"
            }
        if not isinstance(actual_url, str):
            return {
                "status": "error",
                "target": target,
                "technologies": [],
                "technology_count": 0,
                "error": "Invalid response URL"
            }
        try:
            allowed, reason = scope.check(actual_url)
            if not allowed:
                return {
                    "status": "blocked",
                    "target": actual_url,
                    "technologies": [],
                    "technology_count": 0,
                    "error": f"Response URL outside scope: {reason}"
                }
        except (ValueError, TypeError, AttributeError):
            return {
                "status": "error",
                "target": target,
                "technologies": [],
                "technology_count": 0,
                "error": "Invalid response URL"
            }

        return self._analyze(target, response)
