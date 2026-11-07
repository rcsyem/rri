"""DNS Information gathering module for RRI.

Passively collects DNS records (A, AAAA, MX, NS, TXT, CNAME)
for the target domain.  This is information gathering only — the
records here are NOT used to authorise or route any request.  The
SafeDNSResolver in core/dns_resolver.py handles connection safety.

A/AAAA records use the system resolver via socket.getaddrinfo.
MX/NS/TXT/CNAME records require real DNS queries that the Python
standard library cannot perform.  When the ``dns.resolver`` module
from dnspython is available it is used; otherwise those record
types are reported as "not_available" rather than fabricated.
"""

from __future__ import annotations

import socket
from typing import Any
from urllib.parse import urlsplit

from core.models import make_dns_record, make_module_result
from core.network_safety import NetworkSafety

try:
    import dns.resolver as _dns_resolver
    import dns.exception as _dns_exception
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False


_DNS_RECORD_TYPES = ("MX", "NS", "TXT", "CNAME")


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

    @staticmethod
    def _query_dns_record(hostname: str, rtype: str) -> list[str] | None:
        """Query a DNS record type using dnspython if available.

        Returns a list of string representations of the record values,
        or None if the record type cannot be queried (no DNS library).
        An empty list means the query succeeded but no records exist
        (NXDOMAIN or NODATA).
        """
        if not _HAS_DNSPYTHON:
            return None

        try:
            resolver = _dns_resolver.Resolver()
            resolver.lifetime = 5.0
            answers = resolver.resolve(hostname, rtype)
            values: list[str] = []
            for rdata in answers:
                if rtype == "MX":
                    values.append(
                        f"{rdata.preference} {rdata.exchange.to_text()}"
                    )
                else:
                    values.append(rdata.to_text())
            return values
        except _dns_exception.DNSException:
            return []
        except Exception:
            return []

    async def scan(self, target: str) -> dict:
        """Gather DNS records for the target domain.

        A/AAAA records use the system resolver via getaddrinfo.
        MX/NS/TXT/CNAME use dnspython when available; otherwise
        they are reported as not_available.
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
        unsupported_types: list[str] = []

        # A records — via system resolver
        a_records = self._safe_getaddrinfo(hostname, socket.AF_INET)
        if a_records:
            public_a, excl = self._filter_public_ips(a_records)
            excluded_count += excl
            if public_a:
                records.append(
                    make_dns_record("A", hostname, public_a, source="getaddrinfo")
                )

        # AAAA records — via system resolver
        aaaa_records = self._safe_getaddrinfo(hostname, socket.AF_INET6)
        if aaaa_records:
            public_aaaa, excl = self._filter_public_ips(aaaa_records)
            excluded_count += excl
            if public_aaaa:
                records.append(
                    make_dns_record("AAAA", hostname, public_aaaa, source="getaddrinfo")
                )

        # MX / NS / TXT / CNAME — require real DNS queries
        for rtype in _DNS_RECORD_TYPES:
            result = self._query_dns_record(hostname, rtype)
            if result is None:
                unsupported_types.append(rtype)
            elif result:
                records.append(
                    make_dns_record(rtype, hostname, result, source="dns_query")
                )

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
        if unsupported_types:
            result["unsupported_record_types"] = unsupported_types
        return result
