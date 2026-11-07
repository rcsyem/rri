import re

from http.cookies import SimpleCookie


class HeadersAnalyzer:

    SECURITY_HEADERS = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
        "cross-origin-opener-policy": "COOP",
        "cross-origin-resource-policy": "CORP",
        "cross-origin-embedder-policy": "COEP",
    }

    def __init__(self, engine=None):
        self.engine = engine

    @staticmethod
    def _normalize_headers(headers):
        normalized = {}

        if isinstance(headers, dict):
            items = headers.items()

        elif isinstance(headers, (list, tuple)):
            items = headers

        else:
            return normalized

        try:
            for name, value in items:

                if not isinstance(name, str):
                    continue

                key = name.strip().lower()

                if not key:
                    continue

                if isinstance(value, (list, tuple)):
                    values = value
                else:
                    values = [value]

                normalized.setdefault(key, [])

                for item in values:
                    if isinstance(item, str):
                        normalized[key].append(item.strip())

        except (TypeError, ValueError):
            return {}

        return normalized

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
            severity = finding["severity"].lower()

            if severity in counts:
                counts[severity] += 1

        return counts

    @staticmethod
    def _make_finding(
        finding_id,
        title,
        category,
        severity,
        evidence,
        description,
        recommendation
    ):

        return {
            "id": finding_id,
            "title": title,
            "category": category,
            "severity": severity,
            "evidence": evidence,
            "description": description,
            "recommendation": recommendation
        }

    def _check_hsts(self, headers, is_https, findings):

        values = headers.get("strict-transport-security", [])

        if not is_https:
            return

        if not values:
            findings.append(
                self._make_finding(
                    "HSTS_MISSING",
                    "Missing HTTP Strict Transport Security",
                    "Transport Security",
                    "medium",
                    None,
                    "The HTTPS response does not advertise an HSTS policy.",
                    "Configure Strict-Transport-Security with an appropriate max-age."
                )
            )
            return

        value = ", ".join(values)

        match = re.search(
            r"(?:^|;)\s*max-age\s*=\s*(\d+)",
            value,
            re.I
        )

        if not match:
            findings.append(
                self._make_finding(
                    "HSTS_INVALID",
                    "Invalid HSTS max-age",
                    "Transport Security",
                    "medium",
                    value,
                    "The HSTS header does not contain a valid max-age directive.",
                    "Set a valid max-age value in seconds."
                )
            )
            return

        max_age = int(match.group(1))

        if max_age == 0:
            findings.append(
                self._make_finding(
                    "HSTS_DISABLED",
                    "HSTS is disabled",
                    "Transport Security",
                    "medium",
                    value,
                    "A max-age of zero disables HSTS.",
                    "Use an appropriate positive max-age value."
                )
            )

        elif max_age < 15552000:
            findings.append(
                self._make_finding(
                    "HSTS_SHORT_MAX_AGE",
                    "Short HSTS duration",
                    "Transport Security",
                    "low",
                    value,
                    "The HSTS duration is shorter than six months.",
                    "Consider a longer max-age after verifying HTTPS availability."
                )
            )

    def _check_csp(self, headers, findings):

        values = headers.get("content-security-policy", [])

        if not values:
            findings.append(
                self._make_finding(
                    "CSP_MISSING",
                    "Content Security Policy is missing",
                    "Content Security",
                    "medium",
                    None,
                    "No enforced Content-Security-Policy header was detected.",
                    "Define a restrictive CSP based on the resources the application requires."
                )
            )
            return

        value = "; ".join(values)
        lowered = value.lower()

        if "'unsafe-inline'" in lowered:
            findings.append(
                self._make_finding(
                    "CSP_UNSAFE_INLINE",
                    "CSP allows unsafe-inline",
                    "Content Security",
                    "medium",
                    value[:500],
                    "The policy permits inline scripts or styles in applicable directives.",
                    "Prefer nonces or hashes for scripts and avoid unsafe-inline where possible."
                )
            )

        if "'unsafe-eval'" in lowered:
            findings.append(
                self._make_finding(
                    "CSP_UNSAFE_EVAL",
                    "CSP allows unsafe-eval",
                    "Content Security",
                    "medium",
                    value[:500],
                    "The policy permits dynamic evaluation in applicable script directives.",
                    "Remove unsafe-eval where application compatibility allows."
                )
            )

        if re.search(r"(?:^|[\s;])(?:default-src|script-src)\s+\*", lowered):
            findings.append(
                self._make_finding(
                    "CSP_WILDCARD_SOURCE",
                    "CSP contains a wildcard source",
                    "Content Security",
                    "medium",
                    value[:500],
                    "A broad wildcard source may permit resources from untrusted origins.",
                    "Restrict allowed sources to trusted origins."
                )
            )

        if "frame-ancestors" not in lowered:
            findings.append(
                self._make_finding(
                    "CSP_FRAME_ANCESTORS_MISSING",
                    "CSP frame-ancestors directive is missing",
                    "Content Security",
                    "low",
                    value[:500],
                    "The CSP does not explicitly define which sites may embed this page.",
                    "Configure frame-ancestors according to the application's embedding requirements."
                )
            )

    def _check_standard_headers(self, headers, findings):

        checks = [
            (
                "x-frame-options",
                "X_FRAME_OPTIONS_MISSING",
                "Missing X-Frame-Options",
                "medium",
                "Configure X-Frame-Options or use CSP frame-ancestors."
            ),
            (
                "x-content-type-options",
                "NOSNIFF_MISSING",
                "Missing X-Content-Type-Options",
                "low",
                "Set X-Content-Type-Options: nosniff."
            ),
            (
                "referrer-policy",
                "REFERRER_POLICY_MISSING",
                "Missing Referrer-Policy",
                "low",
                "Configure a suitable Referrer-Policy."
            ),
            (
                "permissions-policy",
                "PERMISSIONS_POLICY_MISSING",
                "Missing Permissions-Policy",
                "low",
                "Restrict browser features that the application does not need."
            ),
        ]

        for (
            header,
            finding_id,
            title,
            severity,
            recommendation
        ) in checks:

            if header in headers:
                continue

            if header == "x-frame-options":
                csp = "; ".join(
                    headers.get("content-security-policy", [])
                ).lower()

                if "frame-ancestors" in csp:
                    continue

            findings.append(
                self._make_finding(
                    finding_id,
                    title,
                    "Browser Security",
                    severity,
                    None,
                    f"The {header} response header was not detected.",
                    recommendation
                )
            )

    def _check_isolation_headers(self, headers, findings):

        checks = [
            (
                "cross-origin-opener-policy",
                "COOP_MISSING",
                "Cross-Origin-Opener-Policy is missing"
            ),
            (
                "cross-origin-resource-policy",
                "CORP_MISSING",
                "Cross-Origin-Resource-Policy is missing"
            ),
            (
                "cross-origin-embedder-policy",
                "COEP_MISSING",
                "Cross-Origin-Embedder-Policy is missing"
            ),
        ]

        for header, finding_id, title in checks:

            if header in headers:
                continue

            findings.append(
                self._make_finding(
                    finding_id,
                    title,
                    "Cross-Origin Isolation",
                    "info",
                    None,
                    f"The {header} header was not detected.",
                    "Evaluate whether this isolation policy is needed for the application."
                )
            )

    def _check_information_disclosure(self, headers, findings):

        checks = [
            (
                "server",
                "SERVER_DISCLOSURE",
                "Server information is exposed"
            ),
            (
                "x-powered-by",
                "X_POWERED_BY_DISCLOSURE",
                "Technology information is exposed"
            ),
        ]

        for header, finding_id, title in checks:

            values = headers.get(header, [])

            if not values:
                continue

            findings.append(
                self._make_finding(
                    finding_id,
                    title,
                    "Information Disclosure",
                    "low",
                    ", ".join(values)[:300],
                    f"The response exposes the {header} header.",
                    "Consider minimizing unnecessary server and framework version disclosure."
                )
            )

    def _check_cookies(self, headers, findings):

        cookie_headers = headers.get("set-cookie", [])

        for raw_cookie in cookie_headers:

            cookie = SimpleCookie()

            try:
                cookie.load(raw_cookie)
            except Exception:
                continue

            for name, morsel in cookie.items():

                flags = {
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": morsel["samesite"].lower()
                }

                if not flags["secure"]:
                    findings.append(
                        self._make_finding(
                            "COOKIE_SECURE_MISSING",
                            "Cookie missing Secure attribute",
                            "Cookie Security",
                            "medium",
                            name,
                            f"Cookie '{name}' is not marked Secure.",
                            "Set the Secure attribute for cookies transmitted over HTTPS."
                        )
                    )

                if not flags["httponly"]:
                    findings.append(
                        self._make_finding(
                            "COOKIE_HTTPONLY_MISSING",
                            "Cookie missing HttpOnly attribute",
                            "Cookie Security",
                            "medium",
                            name,
                            f"Cookie '{name}' is accessible to client-side scripts.",
                            "Set HttpOnly for cookies that do not need JavaScript access."
                        )
                    )

                if not flags["samesite"]:
                    findings.append(
                        self._make_finding(
                            "COOKIE_SAMESITE_MISSING",
                            "Cookie missing SameSite attribute",
                            "Cookie Security",
                            "low",
                            name,
                            f"Cookie '{name}' does not specify SameSite.",
                            "Set an appropriate SameSite policy, commonly Lax."
                        )
                    )

                elif flags["samesite"] not in (
                    "strict",
                    "lax",
                    "none"
                ):
                    findings.append(
                        self._make_finding(
                            "COOKIE_SAMESITE_INVALID",
                            "Cookie has an invalid SameSite value",
                            "Cookie Security",
                            "low",
                            name,
                            f"Cookie '{name}' has an unrecognized SameSite value.",
                            "Use Strict, Lax, or None."
                        )
                    )

                if flags["samesite"] == "none" and not flags["secure"]:
                    findings.append(
                        self._make_finding(
                            "COOKIE_SAMESITE_NONE_WITHOUT_SECURE",
                            "SameSite=None cookie lacks Secure",
                            "Cookie Security",
                            "medium",
                            name,
                            f"Cookie '{name}' uses SameSite=None without Secure.",
                            "Add Secure when using SameSite=None."
                        )
                    )

    async def scan(self, target, response=None):

        if self.engine is None:
            return self._error(
                target,
                "HTTP engine is required"
            )

        if response is None:
            try:
                response = await self.engine.fetch(target)
            except Exception as error:
                return self._error(target, str(error))

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

        actual_url = response.get("url", target)

        if self.engine is not None and isinstance(actual_url, str):
            try:
                allowed, reason = self.engine.scope.check(actual_url)
                if not allowed:
                    return self._error(
                        actual_url,
                        f"Response URL outside scope: {reason}",
                        "blocked"
                    )
            except (ValueError, TypeError, AttributeError):
                return self._error(actual_url, "Invalid response URL")

        headers = self._normalize_headers(
            response.get("header_items", response.get("headers", {}))
        )

        findings = []

        is_https = (
            isinstance(actual_url, str)
            and actual_url.lower().startswith("https://")
        )

        self._check_hsts(headers, is_https, findings)
        self._check_csp(headers, findings)
        self._check_standard_headers(headers, findings)
        self._check_isolation_headers(headers, findings)
        self._check_information_disclosure(headers, findings)
        self._check_cookies(headers, findings)

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

        return {
            "status": "completed",
            "target": actual_url,
            "http_status": response.get("http_status"),
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
