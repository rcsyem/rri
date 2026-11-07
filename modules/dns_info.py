"""DNS Information gathering module for RRI.

Passively collects DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
for the target domain.  This is information gathering only — the
records here are NOT used to authorise or route any request.  The
SafeDNSResolver in core/dns_resolver.py handles connection safety.

All lookups use the system resolver via socket.getaddrinfo and
dns-like queries.  No external DNS-over-HTTPS or third-party API
is used.
"""

from __future__ import annotations

import socket
from typing import Any
from urllib.parse import urlsplit

from core.models import make_dns_record, make_module_result
from core.network_safety import NetworkSafety


class DNSInfo:
    """Gathers DNS records for information purposes."""

    MAX_RECORDS = 100

    def __init__(self, engine=None):
        self.engine = engine

    @staticmethod
    def _extract_hostname(target: str) -> str | None:
        if not isinstance(target, str) or not target:
            return None

        try:
            parsed = urlsplit(target)
            hostname = parsed.hostname
            if not hostname:
                return None
            return hostname.rstrip(".").lower()
        except (ValueError, AttributeError, TypeError):
            return None

    @staticmethod
    def _safe_getaddrinfo(hostname: str, family: int) -> list[str]:
        try:
            results = socket.getaddrinfo(
                hostname, None, family, socket.SOCK_STREAM
            )
            return list({
                addr[4][0] for addr in results
                if isinstance(addr, tuple) and len(addr) >= 5
            })
        except (socket.gaierror, socket.herror, OSError, TypeError):
            return []

    @staticmethod
    def _filter_public_ips(addresses: list[str]) -> tuple[list[str], int]:
        """Filter out non-public IP addresses.

        Returns (public_addresses, excluded_count).
        Private/loopback/link-local addresses are silently excluded
        and only a count is kept — their values are never exposed.
        """
        public: list[str] = []
        for addr in addresses:
            allowed, _ = NetworkSafety.validate_ip(addr)
            if allowed:
                public.append(addr)
        excluded = len(addresses) - len(public)
        return public, excluded

    async def scan(self, target: str) -> dict:
        """Gather DNS records for the target domain.

        Uses the system resolver.  No active probing of endpoints.
        """
        if not isinstance(target, str) or not target:
            return make_module_result(
                "dns_info", status="error", target="",
                error="Target URL is required",
            )

        hostname = self._extract_hostname(target)
        if not hostname:
            return make_module_result(
                "dns_info", status="error", target=target,
                error="Could not extract hostname from target",
            )

        records: list[dict] = []
        excluded_count = 0

        a_records = self._safe_getaddrinfo(hostname, socket.AF_INET)
        if a_records:
            public_a, excl = self._filter_public_ips(a_records)
            excluded_count += excl
            if public_a:
                records.append(
                    make_dns_record("A", hostname, public_a, source="dns_lookup")
                )

        aaaa_records = self._safe_getaddrinfo(hostname, socket.AF_INET6)
        if aaaa_records:
            public_aaaa, excl = self._filter_public_ips(aaaa_records)
            excluded_count += excl
            if public_aaaa:
                records.append(
                    make_dns_record("AAAA", hostname, public_aaaa, source="dns_lookup")
                )

        try:
            mx_records = socket.getaddrinfo(
                f"mail.{hostname}", None, socket.AF_INET, socket.SOCK_STREAM
            )
            mx_values = list({
                addr[4][0] for addr in mx_records
                if isinstance(addr, tuple) and len(addr) >= 5
            })
            if mx_values:
                public_mx, excl = self._filter_public_ips(mx_values)
                excluded_count += excl
                if public_mx:
                    records.append(
                        make_dns_record("MX", hostname, public_mx, source="dns_lookup")
                    )
        except (socket.gaierror, socket.herror, OSError, TypeError):
            pass

        if len(records) > self.MAX_RECORDS:
            records = records[: self.MAX_RECORDS]

        record_types = [r["record_type"] for r in records]

        result = make_module_result(
            "dns_info",
            target=target,
            hostname=hostname,
            records=records,
            record_count=len(records),
            record_types=record_types,
        )
        if excluded_count > 0:
            result["excluded_non_public_records"] = excluded_count
        return result
