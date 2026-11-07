"""Tests for modules/tls_analysis.py."""

import asyncio
import socket
import ssl
from unittest.mock import MagicMock, patch

import pytest

from modules.tls_analysis import TLSAnalysis


class TestTLSAnalysisInit:
    def test_defaults(self):
        ta = TLSAnalysis()
        assert ta.engine is None

    def test_with_engine(self):
        engine = MagicMock()
        ta = TLSAnalysis(engine=engine)
        assert ta.engine is engine


class TestTLSAnalysisScan:
    def _mock_safe_resolve(self, ip="192.0.2.1"):
        """Patch NetworkSafety.resolve_and_validate to return a safe public IP."""
        return patch(
            "modules.tls_analysis.NetworkSafety.resolve_and_validate",
            return_value=(True, [ip]),
        )

    def test_empty_target(self):
        ta = TLSAnalysis()
        result = asyncio.run(ta.scan(""))
        assert result["status"] == "error"

    def test_invalid_target(self):
        ta = TLSAnalysis()
        result = asyncio.run(ta.scan("not-a-url"))
        assert result["status"] == "error"

    def test_extracts_hostname(self):
        ta = TLSAnalysis()
        with patch("socket.create_connection", side_effect=socket.error("no connection")):
            with self._mock_safe_resolve():
                result = asyncio.run(ta.scan("https://example.invalid/"))
                assert result["hostname"] == "example.invalid"

    def test_blocked_by_scope(self):
        scope = MagicMock()
        scope.check = MagicMock(return_value=(False, "Out of scope"))
        engine = MagicMock()
        engine.scope = scope

        ta = TLSAnalysis(engine=engine)
        result = asyncio.run(ta.scan("https://evil.com/"))

        assert result["status"] == "blocked"

    def test_connection_error_returns_error(self):
        ta = TLSAnalysis()
        with patch("socket.create_connection", side_effect=socket.error("Connection refused")):
            with self._mock_safe_resolve():
                result = asyncio.run(ta.scan("https://example.invalid/"))

                assert result["status"] == "error"
                assert "Connection refused" in result["error"]

    def test_tls_info_present_on_error(self):
        ta = TLSAnalysis()
        with patch("socket.create_connection", side_effect=socket.error("refused")):
            with self._mock_safe_resolve():
                result = asyncio.run(ta.scan("https://example.invalid/"))

                assert "tls_info" in result
                assert result["tls_info"]["hostname"] == "example.invalid"
                assert result["tls_info"]["error"] is not None

    def test_cert_verification_failure(self):
        ta = TLSAnalysis()

        cert_error = ssl.SSLCertVerificationError(1, "Certificate verification failed", "hostname mismatch")

        mock_sock = MagicMock()
        mock_context = MagicMock()
        mock_context.wrap_socket.side_effect = cert_error

        with patch("socket.create_connection", return_value=mock_sock):
            with patch("ssl.create_default_context", return_value=mock_context):
                with self._mock_safe_resolve():
                    result = asyncio.run(ta.scan("https://example.invalid/"))

                    assert result["cert_valid"] is False
                    assert result["cert_hostname_valid"] is False

    def test_scope_check_uses_https(self):
        scope = MagicMock()
        scope.check = MagicMock(return_value=(True, "ok"))
        engine = MagicMock()
        engine.scope = scope

        ta = TLSAnalysis(engine=engine)

        with patch("socket.create_connection", side_effect=socket.error("refused")):
            with self._mock_safe_resolve():
                asyncio.run(ta.scan("https://example.invalid/"))

                scope.check.assert_called_with("https://example.invalid/")

    def test_no_engine_allows_all(self):
        ta = TLSAnalysis()
        with patch("socket.create_connection", side_effect=socket.error("refused")):
            with self._mock_safe_resolve():
                result = asyncio.run(ta.scan("https://example.invalid/"))
                assert result["status"] == "error"
                assert result["hostname"] == "example.invalid"

    def test_connects_to_validated_ip_not_hostname(self):
        """Verify the TLS connection targets the validated IP, not the raw hostname."""
        ta = TLSAnalysis()
        captured_args = {}

        def capture_connect(args, **kwargs):
            captured_args["address"] = args
            raise socket.error("refused")

        with patch("socket.create_connection", side_effect=capture_connect):
            with self._mock_safe_resolve(ip="203.0.113.5"):
                asyncio.run(ta.scan("https://example.invalid/"))

                assert captured_args["address"][0] == "203.0.113.5"

    def test_rejects_non_public_ip(self):
        """TLS must refuse to connect when DNS resolves to a private IP."""
        ta = TLSAnalysis()
        with patch(
            "modules.tls_analysis.NetworkSafety.resolve_and_validate",
            return_value=(False, "Non-public IP address blocked: 10.0.0.1"),
        ):
            with patch("socket.create_connection") as mock_connect:
                result = asyncio.run(ta.scan("https://example.invalid/"))

                assert result["status"] == "error"
                assert "non-public" in result["error"].lower()
                mock_connect.assert_not_called()

    def test_rejects_loopback_ip(self):
        """TLS must refuse to connect when DNS resolves to 127.0.0.1."""
        ta = TLSAnalysis()
        with patch(
            "modules.tls_analysis.NetworkSafety.resolve_and_validate",
            return_value=(False, "Non-public IP address blocked: 127.0.0.1"),
        ):
            with patch("socket.create_connection") as mock_connect:
                result = asyncio.run(ta.scan("https://example.invalid/"))

                assert result["status"] == "error"
                mock_connect.assert_not_called()

    def test_dns_resolution_failure_returns_error(self):
        """TLS must return an error when DNS resolution fails entirely."""
        ta = TLSAnalysis()
        with patch(
            "modules.tls_analysis.NetworkSafety.resolve_and_validate",
            return_value=(False, "DNS resolution failed"),
        ):
            with patch("socket.create_connection") as mock_connect:
                result = asyncio.run(ta.scan("https://example.invalid/"))

                assert result["status"] == "error"
                mock_connect.assert_not_called()

    def test_sni_preserved_with_server_hostname(self):
        """Verify server_hostname is set to the original hostname for SNI."""
        ta = TLSAnalysis()
        mock_sock = MagicMock()
        mock_tls_sock = MagicMock()
        mock_tls_sock.version.return_value = "TLSv1.3"
        mock_tls_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLS", 3)
        mock_tls_sock.getpeercert.return_value = {}
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_tls_sock)
        mock_context.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        with patch("socket.create_connection", return_value=mock_sock):
            with patch("ssl.create_default_context", return_value=mock_context):
                with self._mock_safe_resolve(ip="203.0.113.5"):
                    asyncio.run(ta.scan("https://example.invalid/"))

                    _, kwargs = mock_context.wrap_socket.call_args
                    assert kwargs["server_hostname"] == "example.invalid"

    def test_no_dns_rebinding_between_validation_and_connection(self):
        """The connection must use the exact IP from resolve_and_validate,
        not re-resolve the hostname."""
        ta = TLSAnalysis()
        captured_args = {}

        def capture_connect(args, **kwargs):
            captured_args["address"] = args
            raise socket.error("refused")

        with patch("socket.create_connection", side_effect=capture_connect):
            with self._mock_safe_resolve(ip="198.51.100.42"):
                asyncio.run(ta.scan("https://example.invalid/"))

                assert captured_args["address"][0] == "198.51.100.42"
                assert captured_args["address"][1] == 443
