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
            result = asyncio.run(di.scan("https://example.invalid/"))
            assert result["hostname"] == "example.invalid"

    def test_records_a_records(self):
        di = DNSInfo()
        def fake_getaddrinfo(hostname, family):
            if family == socket.AF_INET:
                return [self.PUBLIC_A, self.PUBLIC_A2]
            return []
        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=fake_getaddrinfo):
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
            result = asyncio.run(di.scan("https://example.invalid/"))
            aaaa = [r for r in result["records"] if r["record_type"] == "AAAA"]
            assert len(aaaa) == 1
            assert self.PUBLIC_AAAA in aaaa[0]["values"]

    def test_no_records_returns_empty(self):
        di = DNSInfo()
        with patch.object(DNSInfo, "_safe_getaddrinfo", return_value=[]):
            with patch("socket.getaddrinfo", side_effect=socket.gaierror):
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
            result = asyncio.run(di.scan("https://example.invalid/"))
            assert "A" in result["record_types"]

    def test_private_ips_filtered_out(self):
        di = DNSInfo()
        def fake_getaddrinfo(hostname, family):
            if family == socket.AF_INET:
                return ["10.0.0.1", "127.0.0.1", self.PUBLIC_A]
            return []
        with patch.object(DNSInfo, "_safe_getaddrinfo", side_effect=fake_getaddrinfo):
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
            result = asyncio.run(di.scan("https://example.invalid/"))
            assert result.get("excluded_non_public_records") == 1
