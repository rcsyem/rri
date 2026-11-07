import ipaddress
from urllib.parse import urlsplit
import re


class CorrelationEngine:
    SEVERITIES = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4
    }

    CONFIDENCE = {
        "high": 3,
        "medium": 2,
        "low": 1
    }

    MAX_CORRELATIONS = 200
    MAX_EVIDENCE_LENGTH = 300

    def analyze(
        self,
        target,
        technology=None,
        api_discovery=None,
        headers_analysis=None,
        security_checks=None
    ):
        technology = self._valid_result(technology)
        api_discovery = self._valid_result(api_discovery)
        headers_analysis = self._valid_result(headers_analysis)
        security_checks = self._valid_result(security_checks)

        target_origin = self._origin(target)

        technologies = self._items(
            technology, "technologies"
        )

        endpoints = self._items(
            api_discovery, "endpoints"
        )

        header_findings = self._items(
            headers_analysis, "findings"
        )

        security_findings = self._items(
            security_checks, "findings"
        )

        correlations = []

        self._correlate_endpoint_security(
            target_origin,
            endpoints,
            security_findings,
            correlations
        )

        self._correlate_endpoint_headers(
            target_origin,
            endpoints,
            header_findings,
            correlations
        )

        self._correlate_endpoint_technology(
            target_origin,
            endpoints,
            technologies,
            correlations
        )

        correlations = self._deduplicate(correlations)
        correlations = correlations[:self.MAX_CORRELATIONS]

        correlations.sort(
            key=lambda item: (
                self.SEVERITIES.get(item["severity"], 99),
                item["type"],
                item["title"]
            )
        )

        return {
            "status": "completed",
            "target": target,
            "analysis_mode": "passive",
            "summary": {
                "technology_count": len(technologies),
                "endpoint_count": len(endpoints),
                "header_finding_count": len(header_findings),
                "security_finding_count": len(security_findings),
                "correlation_count": len(correlations),
                "severity_counts": self._severity_counts(
                    correlations
                )
            },
            "correlations": correlations,
            "error": None
        }

    @staticmethod
    def _valid_result(result):
        if not isinstance(result, dict):
            return {}

        if result.get("status") != "completed":
            return {}

        return result

    @staticmethod
    def _items(result, key):
        value = result.get(key, [])

        if not isinstance(value, list):
            return []

        return [
            item for item in value
            if isinstance(item, dict)
        ]

    @staticmethod
    def _origin(url):
        """
        Return a normalized HTTP origin:
        (scheme, hostname, effective_port).

        Invalid URLs return None.
        """
        if not isinstance(url, str) or not url:
            return None

        # Reject control characters and surrounding whitespace.
        if url != url.strip():
            return None

        if any(ord(char) < 32 or ord(char) == 127 for char in url):
            return None

        try:
            parts = urlsplit(url)

            scheme = parts.scheme.lower()

            if scheme not in ("http", "https"):
                return None

            if not parts.hostname:
                return None

            if parts.username is not None or parts.password is not None:
                return None

            hostname = parts.hostname.rstrip(".").lower()

            if not hostname:
                return None

            # Normalize IP addresses, including IPv6 representations.
            try:
                hostname = ipaddress.ip_address(hostname).compressed
            except ValueError:
                hostname = hostname.encode("idna").decode("ascii").lower()

                if len(hostname) > 253:
                    return None

                labels = hostname.split(".")

                if any(
                    not label
                    or len(label) > 63
                    or not label[0].isalnum()
                    or not label[-1].isalnum()
                    or any(
                        not (char.isalnum() or char == "-")
                        for char in label
                    )
                    for label in labels
                ):
                    return None

            port = parts.port

            if port is None:
                port = 443 if scheme == "https" else 80

            if not 1 <= port <= 65535:
                return None

            return scheme, hostname, port

        except (ValueError, TypeError, UnicodeError):
            return None

    @classmethod
    def _same_origin(cls, url, target_origin):
        if target_origin is None:
            return False

        endpoint_origin = cls._origin(url)

        return (
            endpoint_origin is not None
            and endpoint_origin == target_origin
        )

    @staticmethod
    def _path(url):
        try:
            return urlsplit(url).path or "/"
        except (ValueError, TypeError):
            return None

    @classmethod
    def _extract_strings(cls, value, depth=0):
        if depth > 5:
            return []

        if isinstance(value, str):
            return [value[:cls.MAX_EVIDENCE_LENGTH]]

        if isinstance(value, dict):
            output = []

            for item in value.values():
                output.extend(
                    cls._extract_strings(item, depth + 1)
                )

            return output

        if isinstance(value, (list, tuple)):
            output = []

            for item in value[:50]:
                output.extend(
                    cls._extract_strings(item, depth + 1)
                )

            return output

        return []

    @classmethod
    def _evidence_contains_path(cls, evidence, path):
        if not isinstance(path, str) or path == "/":
            return False

        strings = cls._extract_strings(evidence)

        pattern = (
            r"(?<![A-Za-z0-9._~-])"
            + re.escape(path)
            + r"(?![A-Za-z0-9._~-])"
        )

        return any(
            re.search(pattern, item)
            for item in strings
        )

    @staticmethod
    def _confidence_rank(value):
        if not isinstance(value, str):
            return 1

        return CorrelationEngine.CONFIDENCE.get(
            value.lower(), 1
        )

    @staticmethod
    def _severity(value):
        if not isinstance(value, str):
            return "info"

        value = value.lower()

        if value not in CorrelationEngine.SEVERITIES:
            return "info"

        return value

    @classmethod
    def _lower_confidence(cls, first, second):
        first_rank = cls._confidence_rank(first)
        second_rank = cls._confidence_rank(second)

        rank = min(first_rank, second_rank)

        for name, value in cls.CONFIDENCE.items():
            if value == rank:
                return name

        return "low"

    @classmethod
    def _correlate_endpoint_security(
        cls,
        target_origin,
        endpoints,
        findings,
        output
    ):
        for endpoint in endpoints:
            endpoint_url = endpoint.get("url")

            if not cls._same_origin(
                endpoint_url, target_origin
            ):
                continue

            endpoint_path = cls._path(endpoint_url)

            for finding in findings:
                evidence = finding.get("evidence")

                if not cls._evidence_contains_path(
                    evidence, endpoint_path
                ):
                    continue

                severity = cls._severity(
                    finding.get("severity")
                )

                output.append({
                    "id": "CORR-ENDPOINT-SECURITY",
                    "type": "endpoint_security_overlap",
                    "title": "API endpoint and security indicator overlap",
                    "severity": severity,
                    "confidence": cls._lower_confidence(
                        endpoint.get("confidence"),
                        finding.get("confidence")
                    ),
                    "entities": {
                        "endpoint": endpoint_url,
                        "security_finding": finding.get(
                            "id", "unknown"
                        )
                    },
                    "evidence": {
                        "endpoint_path": endpoint_path,
                        "security_evidence": evidence
                    },
                    "description": (
                        "The same path appears in API discovery "
                        "and a passive security finding."
                    ),
                    "caveat": (
                        "This is an evidence overlap, not proof "
                        "of an exploitable vulnerability."
                    )
                })

                if len(output) >= cls.MAX_CORRELATIONS:
                    return

    @classmethod
    def _correlate_endpoint_headers(
        cls,
        target_origin,
        endpoints,
        findings,
        output
    ):
        for endpoint in endpoints:
            endpoint_url = endpoint.get("url")

            if not cls._same_origin(
                endpoint_url, target_origin
            ):
                continue

            endpoint_path = cls._path(endpoint_url)

            for finding in findings:
                evidence = finding.get("evidence")

                if not cls._evidence_contains_path(
                    evidence, endpoint_path
                ):
                    continue

                output.append({
                    "id": "CORR-ENDPOINT-HEADERS",
                    "type": "endpoint_header_overlap",
                    "title": "API endpoint and header finding overlap",
                    "severity": cls._severity(
                        finding.get("severity")
                    ),
                    "confidence": cls._lower_confidence(
                        endpoint.get("confidence"),
                        finding.get("confidence")
                    ),
                    "entities": {
                        "endpoint": endpoint_url,
                        "header_finding": finding.get(
                            "id", "unknown"
                        )
                    },
                    "evidence": {
                        "endpoint_path": endpoint_path,
                        "header_evidence": evidence
                    },
                    "description": (
                        "The endpoint path is referenced in "
                        "a header-analysis finding."
                    ),
                    "caveat": (
                        "The relationship does not establish "
                        "that the endpoint is vulnerable."
                    )
                })

                if len(output) >= cls.MAX_CORRELATIONS:
                    return

    @classmethod
    def _correlate_endpoint_technology(
        cls,
        target_origin,
        endpoints,
        technologies,
        output
    ):
        for endpoint in endpoints:
            endpoint_url = endpoint.get("url")

            if not cls._same_origin(
                endpoint_url, target_origin
            ):
                continue

            endpoint_path = cls._path(endpoint_url)

            for technology in technologies:
                evidence = technology.get("evidence")

                if not cls._evidence_contains_path(
                    evidence, endpoint_path
                ):
                    continue

                output.append({
                    "id": "CORR-ENDPOINT-TECHNOLOGY",
                    "type": "endpoint_technology_evidence",
                    "title": "API endpoint referenced in technology evidence",
                    "severity": "info",
                    "confidence": cls._lower_confidence(
                        technology.get("confidence"),
                        endpoint.get("confidence")
                    ),
                    "entities": {
                        "endpoint": endpoint_url,
                        "technology": technology.get(
                            "name", "unknown"
                        )
                    },
                    "evidence": {
                        "endpoint_path": endpoint_path,
                        "technology_evidence": evidence
                    },
                    "description": (
                        "Technology evidence contains the "
                        "same path discovered as an API endpoint."
                    ),
                    "caveat": (
                        "This does not prove that the technology "
                        "implements or controls the endpoint."
                    )
                })

                if len(output) >= cls.MAX_CORRELATIONS:
                    return

    @staticmethod
    def _deduplicate(items):
        unique = {}

        for item in items:
            key = (
                item["type"],
                str(item["entities"]),
                str(item["evidence"])
            )

            unique[key] = item

        return list(unique.values())

    @classmethod
    def _severity_counts(cls, findings):
        counts = {
            name: 0 for name in cls.SEVERITIES
        }

        for finding in findings:
            severity = finding.get("severity", "info")

            if severity not in counts:
                severity = "info"

            counts[severity] += 1

        return counts
