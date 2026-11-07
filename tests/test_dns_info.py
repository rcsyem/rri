"""Tests for modules/dns_info.py."""

import asyncio
import socket
from unittest.mock import MagicMock, patch

import pytest

from modules.dns_info import DNSInfo


class TestDNSInfoInit:
    def test_defaults(self):
        di = DNSInfo()
        assert di.engine is None

    def test_with_engine(self):
        engine = MagicMock()
        di = DNSInfo(engine=engine)
        assert di.engine is engine


class TestDNSInfoScan:
    PUBLIC_A = "93.184.216.34"
    PUBLIC_A2 = "93.184.216.35"
    PUBLIC_AAAA = "2606:2800:220:1:248:1893:25c8:1946"

    def _patch_no_dns_query(self):
        """Patch _query_dns_record to return None (unsupported)."""
        return patch.object(DNSInfo, "_query_dns_record", return_value=None)

    def test_empty_target(self):
        di = DNSInfo()
        result = asyncio.run(di.scan(""))
        assert result["status"] == "error"

    def test_invalid_target(self):
        di = DNSInfo()
        result = asyncio.run(di.scan("not-a-url"))
        assert result["status"] == "error"

    def test_extracts_hostname(self):
        di = DNSInfo()
        with patch.object(DNSInfo, "_safe_getaddrinfo", return_value=[]):
            with self._patch_no_dns_query():
                result = asyncio.run(di.scan("https://example.invalid/"))
                assert result["hostname"] == "example.invalid"

    def test_records_a_records(self):
        di = DNSInfo()
        def fake_getaddrinfo(hostname, family):
            if family == socket.AF_INET:
                return [self.PUBLIC_A, self.PUBLIC_A2]
            return []
        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=fake_getaddrinfo):
            with self._patch_no_dns_query():
                result = asyncio.run(di.scan("https://example.invalid/"))
                assert result["status"] == "completed"
                a_record = [r for r in result["records"] if r["record_type"] == "A"]
                assert len(a_record) == 1
                assert self.PUBLIC_A in a_record[0]["values"]
                assert self.PUBLIC_A2 in a_record[0]["values"]

    def test_records_aaaa_records(self):
        di = DNSInfo()
        def fake_getaddrinfo(hostname, family):
            if family == socket.AF_INET6:
                return [self.PUBLIC_AAAA]
            return []
        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=fake_getaddrinfo):
            with self._patch_no_dns_query():
                result = asyncio.run(di.scan("https://example.invalid/"))
                aaaa = [r for r in result["records"] if r["record_type"] == "AAAA"]
                assert len(aaaa) == 1
                assert self.PUBLIC_AAAA in aaaa[0]["values"]

    def test_no_records_returns_empty(self):
        di = DNSInfo()
        with patch.object(DNSInfo, "_safe_getaddrinfo", return_value=[]):
            with patch("socket.getaddrinfo", side_effect=socket.gaierror):
                with self._patch_no_dns_query():
                    result = asyncio.run(di.scan("https://example.invalid/"))
                    assert result["record_count"] == 0
                    assert result["records"] == []

    def test_record_types_in_result(self):
        di = DNSInfo()
        def fake_getaddrinfo(hostname, family):
            if family == socket.AF_INET:
                return [self.PUBLIC_A]
            return []
        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=fake_getaddrinfo):
            with self._patch_no_dns_query():
                result = asyncio.run(di.scan("https://example.invalid/"))
                assert "A" in result["record_types"]

    def test_private_ips_filtered_out(self):
        di = DNSInfo()
        def fake_getaddrinfo(hostname, family):
            if family == socket.AF_INET:
                return ["10.0.0.1", "127.0.0.1", self.PUBLIC_A]
            return []
        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=fake_getaddrinfo):
            with self._patch_no_dns_query():
                result = asyncio.run(di.scan("https://example.invalid/"))
                a_record = [r for r in result["records"] if r["record_type"] == "A"]
                assert len(a_record) == 1
                assert self.PUBLIC_A in a_record[0]["values"]
                assert "10.0.0.1" not in a_record[0]["values"]
                assert "127.0.0.1" not in a_record[0]["values"]

    def test_all_private_ips_excluded(self):
        di = DNSInfo()
        def fake_getaddrinfo(hostname, family):
            if family == socket.AF_INET:
                return ["10.0.0.1", "192.168.1.1"]
            return []
        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=fake_getaddrinfo):
            with self._patch_no_dns_query():
                result = asyncio.run(di.scan("https://example.invalid/"))
                assert result["record_count"] == 0
                assert result.get("excluded_non_public_records") == 2

    def test_excluded_count_reported(self):
        di = DNSInfo()
        def fake_getaddrinfo(hostname, family):
            if family == socket.AF_INET:
                return ["10.0.0.1", self.PUBLIC_A]
            return []
        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=fake_getaddrinfo):
            with self._patch_no_dns_query():
                result = asyncio.run(di.scan("https://example.invalid/"))
                assert result.get("excluded_non_public_records") == 1


class TestDNSRecordTypes:
    """Tests for MX/NS/TXT/CNAME record collection via _query_dns_record."""

    PUBLIC_A = "93.184.216.34"

    def _fake_getaddrinfo(self, hostname, family):
        if family == socket.AF_INET:
            return [self.PUBLIC_A]
        return []

    def test_mx_records_via_dns_query(self):
        di = DNSInfo()
        mx_values = ["10 mail.example.invalid.", "20 backup.example.invalid."]

        def fake_query(hostname, rtype):
            if rtype == "MX":
                return mx_values
            return []

        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=self._fake_getaddrinfo):
            with patch.object(DNSInfo, "_query_dns_record", side_effect=fake_query):
                result = asyncio.run(di.scan("https://example.invalid/"))
                mx = [r for r in result["records"] if r["record_type"] == "MX"]
                assert len(mx) == 1
                assert "10 mail.example.invalid." in mx[0]["values"]
                assert "20 backup.example.invalid." in mx[0]["values"]
                assert mx[0]["discovery_source"] == "dns_query"

    def test_ns_records_via_dns_query(self):
        di = DNSInfo()
        ns_values = ["ns1.example.invalid.", "ns2.example.invalid."]

        def fake_query(hostname, rtype):
            if rtype == "NS":
                return ns_values
            return []

        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=self._fake_getaddrinfo):
            with patch.object(DNSInfo, "_query_dns_record", side_effect=fake_query):
                result = asyncio.run(di.scan("https://example.invalid/"))
                ns = [r for r in result["records"] if r["record_type"] == "NS"]
                assert len(ns) == 1
                assert "ns1.example.invalid." in ns[0]["values"]

    def test_txt_records_via_dns_query(self):
        di = DNSInfo()
        txt_values = ['"v=spf1 -all"']

        def fake_query(hostname, rtype):
            if rtype == "TXT":
                return txt_values
            return []

        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=self._fake_getaddrinfo):
            with patch.object(DNSInfo, "_query_dns_record", side_effect=fake_query):
                result = asyncio.run(di.scan("https://example.invalid/"))
                txt = [r for r in result["records"] if r["record_type"] == "TXT"]
                assert len(txt) == 1
                assert '"v=spf1 -all"' in txt[0]["values"]

    def test_cname_records_via_dns_query(self):
        di = DNSInfo()
        cname_values = ["alias.example.invalid."]

        def fake_query(hostname, rtype):
            if rtype == "CNAME":
                return cname_values
            return []

        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=self._fake_getaddrinfo):
            with patch.object(DNSInfo, "_query_dns_record", side_effect=fake_query):
                result = asyncio.run(di.scan("https://example.invalid/"))
                cname = [r for r in result["records"] if r["record_type"] == "CNAME"]
                assert len(cname) == 1
                assert "alias.example.invalid." in cname[0]["values"]

    def test_unsupported_types_reported(self):
        di = DNSInfo()
        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=self._fake_getaddrinfo):
            with patch.object(DNSInfo, "_query_dns_record", return_value=None):
                result = asyncio.run(di.scan("https://example.invalid/"))
                unsupported = result.get("unsupported_record_types", [])
                assert "MX" in unsupported
                assert "NS" in unsupported
                assert "TXT" in unsupported
                assert "CNAME" in unsupported
                # A should still be present
                assert "A" in result["record_types"]
                # MX should NOT be in record_types
                assert "MX" not in result["record_types"]

    def test_empty_dns_query_returns_no_record(self):
        di = DNSInfo()
        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=self._fake_getaddrinfo):
            with patch.object(DNSInfo, "_query_dns_record", return_value=[]):
                result = asyncio.run(di.scan("https://example.invalid/"))
                # A record present, but no MX/NS/TXT/CNAME
                types = result["record_types"]
                assert "A" in types
                assert "MX" not in types
                assert "NS" not in types
                # Not unsupported — just empty results
                assert "unsupported_record_types" not in result

    def test_no_fake_mx_from_getaddrinfo(self):
        """Ensure A/AAAA results are never labeled as MX."""
        di = DNSInfo()

        def fake_getaddrinfo(hostname, family):
            if family == socket.AF_INET:
                # Even if mail.{hostname} resolves, it must NOT appear as MX
                return [self.PUBLIC_A]
            return []

        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=fake_getaddrinfo):
            with patch.object(DNSInfo, "_query_dns_record", return_value=None):
                result = asyncio.run(di.scan("https://example.invalid/"))
                mx = [r for r in result["records"] if r["record_type"] == "MX"]
                assert mx == []
                a = [r for r in result["records"] if r["record_type"] == "A"]
                assert len(a) == 1
                assert a[0]["discovery_source"] == "getaddrinfo"

    def test_all_record_types_collected(self):
        di = DNSInfo()
        query_map = {
            "MX": ["10 mail.example.invalid."],
            "NS": ["ns1.example.invalid."],
            "TXT": ['"v=spf1 -all"'],
            "CNAME": ["alias.example.invalid."],
        }

        def fake_query(hostname, rtype):
            return query_map.get(rtype, [])

        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=self._fake_getaddrinfo):
            with patch.object(DNSInfo, "_query_dns_record", side_effect=fake_query):
                result = asyncio.run(di.scan("https://example.invalid/"))
                types = set(result["record_types"])
                assert types == {"A", "MX", "NS", "TXT", "CNAME"}
