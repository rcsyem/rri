"""TLS/SSL Analysis module for RRI.

Passively inspects TLS connection and certificate information for
the target hostname.  Uses Python's ssl module to connect and extract:
  - TLS version negotiated
  - Cipher suite
  - Certificate validity (dates, issuer, subject)
  - Hostname verification result

This module does NOT send HTTP requests — it only establishes a TLS
connection to inspect the certificate.  The connection is made to the
standard HTTPS port (443) only, and the hostname must be in scope.

DNS resolution is performed via NetworkSafety.resolve_and_validate to
ensure the resolved IP address is public and not private/loopback.
The TLS connection is made to the verified IP address directly,
preventing DNS rebinding between validation and connection.  SNI is
preserved using the original hostname via server_hostname.

All certificate data is extracted from the peer certificate via
ssl.SSLSocket.getpeercert() and is passive observation only.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from core.models import make_tls_info, make_module_result
from core.network_safety import NetworkSafety


class TLSAnalysis:
    """Inspects TLS/SSL connection and certificate information."""

    DEFAULT_PORT = 443
    TIMEOUT = 10
    MAX_CERT_FIELDS = 50

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
    def _format_cert_name(name_dict: dict) -> str | None:
        if not isinstance(name_dict, dict):
            return None

        parts = []
        for rdn in sorted(name_dict.keys()):
            value = name_dict[rdn]
            if isinstance(value, str):
                parts.append(f"{rdn}={value}")
            elif isinstance(value, tuple):
                parts.append(f"{rdn}={','.join(str(v) for v in value)}")

        return ", ".join(parts) if parts else None

    @staticmethod
    def _cert_date(value: str) -> str | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            dt = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except (ValueError, TypeError):
            return value

    def _check_scope(self, hostname: str) -> bool:
        if self.engine is None:
            return True

        test_url = f"https://{hostname}/"
        allowed, _ = self.engine.scope.check(test_url)
        return allowed

    @staticmethod
    def _resolve_safe_ip(hostname: str) -> str | None:
        """Resolve hostname to a validated public IP address.

        Uses NetworkSafety.resolve_and_validate which checks every
        resolved address against private/loopback/link-local ranges.
        Returns the first valid public IP, or None if no safe address
        is found.
        """
        ok, result = NetworkSafety.resolve_and_validate(hostname)
        if not ok or not isinstance(result, list) or not result:
            return None
        return result[0]

    async def scan(self, target: str) -> dict:
        """Inspect TLS certificate and connection for the target.

        Args:
            target: the seed URL (hostname extracted from it)

        Returns:
            Module result with tls_info dict containing certificate
            and connection details.
        """
        if not isinstance(target, str) or not target:
            return make_module_result(
                "tls_analysis", status="error", target="",
                error="Target URL is required",
            )

        hostname = self._extract_hostname(target)
        if not hostname:
            return make_module_result(
                "tls_analysis", status="error", target=target,
                error="Could not extract hostname from target",
            )

        if not self._check_scope(hostname):
            return make_module_result(
                "tls_analysis", status="blocked", target=target,
                error=f"Hostname {hostname} outside scope",
            )

        safe_ip = self._resolve_safe_ip(hostname)
        if safe_ip is None:
            tls_info = make_tls_info(
                hostname=hostname,
                error="DNS resolution failed or returned non-public addresses",
            )
            return make_module_result(
                "tls_analysis", status="error", target=target,
                hostname=hostname,
                tls_info=tls_info,
                error="DNS resolution failed or returned non-public addresses",
            )

        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection(
                (safe_ip, self.DEFAULT_PORT),
                timeout=self.TIMEOUT,
            ) as sock:
                with context.wrap_socket(
                    sock, server_hostname=hostname
                ) as tls_sock:
                    cert = tls_sock.getpeercert()
                    tls_version = tls_sock.version()
                    cipher = tls_sock.cipher()

                    cert_valid = True
                    cert_hostname_valid = True
                    cert_not_before = None
                    cert_not_after = None
                    cert_issuer = None
                    cert_subject = None

                    if cert:
                        cert_not_before = self._cert_date(
                            cert.get("notBefore")
                        )
                        cert_not_after = self._cert_date(
                            cert.get("notAfter")
                        )
                        cert_issuer = self._format_cert_name(
                            cert.get("issuer", {})
                        )
                        cert_subject = self._format_cert_name(
                            cert.get("subject", {})
                        )

                    cipher_suite = cipher[0] if cipher else None

                    tls_info = make_tls_info(
                        hostname=hostname,
                        tls_version=tls_version,
                        cipher_suite=cipher_suite,
                        cert_valid=cert_valid,
                        cert_hostname_valid=cert_hostname_valid,
                        cert_not_before=cert_not_before,
                        cert_not_after=cert_not_after,
                        cert_issuer=cert_issuer,
                        cert_subject=cert_subject,
                    )

                    return make_module_result(
                        "tls_analysis",
                        target=target,
                        hostname=hostname,
                        tls_info=tls_info,
                        tls_version=tls_version,
                        cipher_suite=cipher_suite,
                        cert_valid=cert_valid,
                        cert_hostname_valid=cert_hostname_valid,
                        cert_issuer=cert_issuer,
                        cert_subject=cert_subject,
                        cert_not_before=cert_not_before,
                        cert_not_after=cert_not_after,
                    )

        except ssl.SSLCertVerificationError as e:
            reason = getattr(e, "verify_message", None) or str(e)
            tls_info = make_tls_info(
                hostname=hostname,
                cert_valid=False,
                cert_hostname_valid=False,
                error=f"Certificate verification failed: {reason}",
            )

            return make_module_result(
                "tls_analysis",
                target=target,
                hostname=hostname,
                tls_info=tls_info,
                cert_valid=False,
                cert_hostname_valid=False,
                error=f"Certificate verification failed: {reason}",
            )

        except (ssl.SSLError, socket.error, OSError, TimeoutError) as e:
            tls_info = make_tls_info(
                hostname=hostname,
                error=str(e),
            )

            return make_module_result(
                "tls_analysis",
                status="error",
                target=target,
                hostname=hostname,
                tls_info=tls_info,
                error=str(e),
            )
