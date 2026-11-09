import re

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit


class SecurityPageParser(HTMLParser):

    def __init__(self):
        super().__init__(convert_charrefs=True)

        self.references = []
        self.title = ""
        self._inside_title = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag.lower() == "title":
            self._inside_title = True

        for attribute in ("href", "src", "action"):
            value = attrs.get(attribute)

            if isinstance(value, str) and value.strip():
                self.references.append(value.strip())

    def handle_data(self, data):
        if self._inside_title:
            self.title += data

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._inside_title = False


class SecurityChecks:

    MAX_BODY_ANALYSIS = 2 * 1024 * 1024
    MAX_FINDINGS = 100
    MAX_EVIDENCE_LENGTH = 300

    ADMIN_PATH_PATTERN = re.compile(
        r"(?:^|/)(?:admin|administrator|wp-admin|dashboard|manage)(?:/|$)",
        re.I
    )

    SENSITIVE_PATH_PATTERN = re.compile(
        r"(?:^|/)"
        r"(?:"
        r"\.env(?:\.[a-z0-9._-]+)?"
        r"|[^/]+\.(?:bak|backup|old|orig|save|swp|sql|dump|zip|tar|gz|7z)"
        r")"
        r"(?:$|[?#])",
        re.I
    )

    SOURCE_MAP_PATTERN = re.compile(
        r"sourceMappingURL\s*=\s*([^\s*]+)",
        re.I
    )

    DEBUG_PATTERNS = (
        ("Laravel Ignition", re.compile(r"Laravel Ignition", re.I)),
        ("Whoops error page", re.compile(r"Whoops[!,]", re.I)),
        ("Werkzeug debugger", re.compile(r"Werkzeug Debugger", re.I)),
        ("Django debug page", re.compile(r"Technical 500 error|Django.*DEBUG", re.I)),
        ("Symfony exception page", re.compile(r"Symfony Exception", re.I)),
        ("ASP.NET error page", re.compile(r"Server Error in '/' Application", re.I)),
    )

    ERROR_PATTERNS = (
        ("Python traceback", re.compile(r"Traceback \(most recent call last\)", re.I)),
        ("Java exception", re.compile(r"\b(?:java|javax)\.[\w.]+Exception\b")),
        ("SQL error", re.compile(r"\bSQLSTATE\b|SQL syntax.*error", re.I)),
        ("Database exception", re.compile(r"\b(?:PDOException|mysqli_sql_exception)\b", re.I)),
        ("PHP fatal error", re.compile(r"\bFatal error\s*:", re.I)),
        ("Python exception", re.compile(r"\b(?:ValueError|TypeError|KeyError|ImportError):")),
        ("Stack trace", re.compile(r"\bat\s+[\w.$]+\([^)]*:\d+\)")),
    )

    CONFIG_KEY_PATTERN = re.compile(
        r"(?im)^\s*"
        r"(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|"
        r"DB_PASSWORD|DATABASE_URL|SECRET_KEY|APP_KEY|"
        r"PRIVATE_KEY|API_SECRET)"
        r"\s*[:=]\s*(\S+)"
    )

    INTERNAL_PATH_PATTERN = re.compile(
        r"(?:/var/www/|/home/[^/\s]+/|/srv/www/|"
        r"C:\\inetpub\\|C:\\xampp\\)",
        re.I
    )

    PRIVATE_IP_PATTERN = re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
    )

    def __init__(self, engine=None):
        self.engine = engine

    @staticmethod
    def _decode_body(body):

        if isinstance(body, bytes):
            return body.decode("utf-8", errors="replace")

        if isinstance(body, str):
            return body

        return ""

    @staticmethod
    def _same_origin_path(base_url, reference):

        if not isinstance(reference, str):
            return None

        try:
            resolved = urlsplit(urljoin(base_url, reference))
            base = urlsplit(base_url)

            if (
                resolved.scheme.lower() != base.scheme.lower()
                or resolved.hostname != base.hostname
                or resolved.port != base.port
                or resolved.username
                or resolved.password
            ):
                return None

            return resolved.path or "/"

        except (TypeError, ValueError):
            return None

    def _finding(
        self,
        finding_id,
        title,
        category,
        severity,
        confidence,
        evidence,
        description,
        recommendation
    ):

        return {
            "id": finding_id,
            "title": title,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "evidence": str(evidence)[:self.MAX_EVIDENCE_LENGTH],
            "description": description,
            "recommendation": recommendation
        }

    def _analyze_references(self, parser, target, findings):

        seen = set()

        for reference in parser.references:

            path = self._same_origin_path(target, reference)

            if not path or path in seen:
                continue

            seen.add(path)

            if self.ADMIN_PATH_PATTERN.search(path):

                findings.append(
                    self._finding(
                        "ADMIN_INTERFACE_REFERENCE",
                        "Administrative interface reference",
                        "Administrative Exposure",
                        "info",
                        "high",
                        path,
                        "The page references a path commonly associated with an administrative interface. This does not establish unauthorized access.",
                        "Verify that administrative interfaces require authentication and appropriate authorization."
                    )
                )

            if self.SENSITIVE_PATH_PATTERN.search(path):

                findings.append(
                    self._finding(
                        "SENSITIVE_FILE_REFERENCE",
                        "Sensitive file reference",
                        "Sensitive Resource Reference",
                        "low",
                        "medium",
                        path,
                        "The page references a filename or path commonly associated with configuration, backups, or database files. Exposure has not been confirmed.",
                        "Review whether the referenced resource is necessary and ensure sensitive files cannot be accessed publicly."
                    )
                )

    def _analyze_source_maps(self, body, target, findings):

        for match in self.SOURCE_MAP_PATTERN.finditer(body):

            reference = match.group(1).strip("'\"`")

            path = self._same_origin_path(target, reference)

            if path is None:
                continue

            findings.append(
                self._finding(
                    "SOURCE_MAP_REFERENCE",
                    "JavaScript source map reference",
                    "Source Map Exposure",
                    "info",
                    "high",
                    path,
                    "A JavaScript source map is referenced in the response. Its availability and contents have not been checked.",
                    "Review whether production source maps should be publicly accessible."
                )
            )

    def _analyze_debug(self, body, findings):

        for name, pattern in self.DEBUG_PATTERNS:

            if pattern.search(body):

                findings.append(
                    self._finding(
                        "DEBUG_PAGE_INDICATOR",
                        "Debug page indicator",
                        "Debug Exposure",
                        "high",
                        "medium",
                        name,
                        "The response contains an indicator associated with a framework debug or diagnostic page.",
                        "Disable public debug pages and ensure production error handling does not expose diagnostic information."
                    )
                )

    def _analyze_errors(self, body, findings):

        for name, pattern in self.ERROR_PATTERNS:

            if pattern.search(body):

                findings.append(
                    self._finding(
                        "ERROR_DETAIL_DISCLOSURE",
                        "Detailed error information detected",
                        "Error Information Disclosure",
                        "medium",
                        "medium",
                        name,
                        "The response contains a pattern associated with an application or database error.",
                        "Review the response and use generic public error messages while keeping detailed diagnostics in protected logs."
                    )
                )

                break

    def _analyze_configuration(self, body, findings):

        matches = list(self.CONFIG_KEY_PATTERN.finditer(body))

        if not matches:
            return

        keys = sorted({
            match.group(1)
            for match in matches
        })

        findings.append(
            self._finding(
                "CONFIGURATION_VALUE_INDICATOR",
                "Potential configuration value disclosure",
                "Sensitive Information Disclosure",
                "high",
                "medium",
                "Configuration keys detected: " + ", ".join(keys),
                "The response contains lines resembling sensitive configuration assignments. The values are deliberately excluded from the report.",
                "Verify whether these values are genuine secrets. Rotate exposed credentials and prevent configuration files from being served publicly."
            )
        )

    def _analyze_directory_listing(self, body, parser, findings):

        title = parser.title.strip()

        indicator = re.search(
            r"(?:^|\s)Index of\s+/",
            title,
            re.I
        )

        heading = re.search(
            r"<h1[^>]*>\s*Index of\s+/",
            body,
            re.I
        )

        if indicator or heading:

            findings.append(
                self._finding(
                    "DIRECTORY_LISTING_INDICATOR",
                    "Directory listing indicator",
                    "Directory Listing",
                    "medium",
                    "medium",
                    title or "Index of heading detected",
                    "The response resembles a web server directory index. Actual directory contents and sensitivity have not been assessed.",
                    "Disable directory indexing unless explicitly required."
                )
            )

    def _analyze_internal_details(self, body, findings):

        internal_path = self.INTERNAL_PATH_PATTERN.search(body)

        private_ip = self.PRIVATE_IP_PATTERN.search(body)

        if internal_path or private_ip:

            evidence = []

            if internal_path:
                evidence.append("Internal filesystem path pattern")

            if private_ip:
                evidence.append("Private IPv4 address pattern")

            findings.append(
                self._finding(
                    "INTERNAL_DETAIL_DISCLOSURE",
                    "Potential internal infrastructure detail",
                    "Information Disclosure",
                    "low",
                    "low",
                    ", ".join(evidence),
                    "The response contains patterns resembling internal filesystem paths or private IP addresses.",
                    "Review whether these details are intentionally disclosed and remove unnecessary internal information from public responses."
                )
            )

    @staticmethod
    def _severity_counts(findings):

        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for finding in findings:
            severity = finding["severity"]

            if severity in counts:
                counts[severity] += 1

        return counts

    async def scan(self, target, response=None):

        if response is None:

            if self.engine is None:
                return self._error(target, "HTTP engine is required")

            try:
                response = await self.engine.fetch(target)

            except Exception as error:
                return self._error(target, str(error))

        if not isinstance(response, dict):
            return self._error(target, "Invalid HTTP response")

        if response.get("status") != "completed":
            return self._error(
                target,
                response.get("error") or "Page fetch failed",
                response.get("status", "error")
            )

        actual_url = response.get("url", target)

        if not isinstance(actual_url, str):
            return self._error(target, "Invalid response URL")

        scope = getattr(self.engine, "scope", None) if self.engine else None
        if scope is None:
            return self._error(
                actual_url,
                "No scope engine available — cannot verify response URL",
                "blocked"
            )
        try:
            allowed, reason = scope.check(actual_url)
            if not allowed:
                return self._error(
                    actual_url,
                    f"Response URL outside scope: {reason}",
                    "blocked"
                )
        except (ValueError, TypeError, AttributeError):
            return self._error(actual_url, "Invalid response URL")

        body = self._decode_body(response.get("body", b""))

        body = body[:self.MAX_BODY_ANALYSIS]

        parser = SecurityPageParser()

        try:
            parser.feed(body)
            parser.close()
        except Exception:
            pass

        findings = []

        self._analyze_references(parser, actual_url, findings)
        self._analyze_source_maps(body, actual_url, findings)
        self._analyze_debug(body, findings)
        self._analyze_errors(body, findings)
        self._analyze_configuration(body, findings)
        self._analyze_directory_listing(body, parser, findings)
        self._analyze_internal_details(body, findings)

        unique = {}
        for finding in findings:
            key = (finding["id"], finding["evidence"])
            unique[key] = finding

        findings = list(unique.values())

        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4
        }

        findings.sort(
            key=lambda item: (
                severity_order[item["severity"]],
                item["id"]
            )
        )

        findings = findings[:self.MAX_FINDINGS]

        return {
            "status": "completed",
            "target": actual_url,
            "http_status": response.get("http_status"),
            "analysis_mode": "passive",
            "findings": findings,
            "finding_count": len(findings),
            "severity_counts": self._severity_counts(findings),
            "error": None
        }

    @staticmethod
    def _error(target, message, status="error"):

        return {
            "status": status,
            "target": target,
            "http_status": None,
            "analysis_mode": "passive",
            "findings": [],
            "finding_count": 0,
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "error": message
        }
