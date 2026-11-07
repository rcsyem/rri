"""Unified data models for RRI recon results.

Every recon engine returns a dict with a "status" key and a list of
typed result dicts.  These helpers centralise field names, validation,
and safe defaults so that reporting, correlation, and future modules
share one consistent shape.

Design principles
~~~~~~~~~~~~~~~~~

* **Discovery vs verification** -- every result carries a ``discovery_source``
  (where the item was found) and a ``verification_status`` that is one of:
  ``discovered`` (mentioned somewhere but not fetched),
  ``tested`` (an HTTP request was made),
  ``confirmed`` (the request returned a success-like status), or
  ``failed`` (the request returned an error or timed out).

* **Evidence-first** -- every finding includes an ``evidence`` field so that
  reports can show *why* something was reported, never just *what*.

* **No active probing** -- these models describe passive observations only.
  No field implies that a request was sent to an API endpoint.

* **Immutable defaults** -- factory functions return fresh dicts so callers
  never share mutable state accidentally.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERIFICATION_STATUSES = ("discovered", "tested", "confirmed", "failed")

CONFIDENCE_LEVELS = ("high", "medium", "low")

SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info")

MAX_EVIDENCE_LENGTH = 500
MAX_URL_LENGTH = 2048
MAX_PATH_LENGTH = 2048


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def validate_url(url: Any) -> str:
    """Return a cleaned URL string or raise ``ValueError``."""
    if not isinstance(url, str) or not url:
        raise ValueError("URL must be a non-empty string")

    url = url.strip()

    if len(url) > MAX_URL_LENGTH:
        raise ValueError("URL exceeds maximum length")

    if any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError("URL contains control characters")

    if "\\" in url:
        raise ValueError("Backslashes are not allowed in URLs")

    return url


def validate_path(path: Any) -> str:
    """Return a validated path string or raise ``ValueError``."""
    if not isinstance(path, str) or not path:
        raise ValueError("Path must be a non-empty string")

    if len(path) > MAX_PATH_LENGTH:
        raise ValueError("Path exceeds maximum length")

    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        raise ValueError("Path contains control characters")

    return path


def validate_severity(value: Any) -> str:
    """Return a normalised severity or ``'info'``."""
    if not isinstance(value, str):
        return "info"
    lowered = value.lower()
    return lowered if lowered in SEVERITY_LEVELS else "info"


def validate_confidence(value: Any) -> str:
    """Return a normalised confidence or ``'low'``."""
    if not isinstance(value, str):
        return "low"
    lowered = value.lower()
    return lowered if lowered in CONFIDENCE_LEVELS else "low"


def validate_verification(value: Any) -> str:
    """Return a normalised verification status or ``'discovered'``."""
    if not isinstance(value, str):
        return "discovered"
    lowered = value.lower()
    return lowered if lowered in VERIFICATION_STATUSES else "discovered"


def truncate_evidence(value: Any) -> str:
    """Return a string representation capped at ``MAX_EVIDENCE_LENGTH``."""
    text = str(value if value is not None else "")
    if len(text) > MAX_EVIDENCE_LENGTH:
        text = text[:MAX_EVIDENCE_LENGTH]
    return text


def origin_from_url(url: Any) -> tuple[str, str, int] | None:
    """Return ``(scheme, hostname, port)`` or ``None`` for invalid URLs."""
    if not isinstance(url, str) or not url:
        return None

    if url != url.strip():
        return None

    if any(ord(c) < 32 or ord(c) == 127 for c in url):
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

        try:
            hostname = ipaddress.ip_address(hostname).compressed
        except ValueError:
            hostname = hostname.encode("idna").decode("ascii").lower()
            if len(hostname) > 253:
                return None

        port = parts.port
        if port is None:
            port = 443 if scheme == "https" else 80

        if not 1 <= port <= 65535:
            return None

        return scheme, hostname, port

    except (ValueError, TypeError, UnicodeError):
        return None


def path_from_url(url: Any) -> str | None:
    """Return the path component of *url* or ``None``."""
    if not isinstance(url, str) or not url:
        return None
    try:
        return urlsplit(url).path or "/"
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Factory functions -- one per result type
# ---------------------------------------------------------------------------

def make_discovered_url(
    url: str,
    source: str,
    verification: str = "discovered",
    http_status: int | None = None,
    content_type: str | None = None,
    redirect_url: str | None = None,
    error: str | None = None,
) -> dict:
    """A URL found during recon (from HTML, JS, crawling, etc.).

    ``verification`` distinguishes between URLs that were merely
    *discovered* (mentioned in content), *tested* (fetched), *confirmed*
    (fetch succeeded), or *failed* (fetch errored).
    """
    url = validate_url(url)
    return {
        "url": url,
        "discovery_source": str(source) if source else "unknown",
        "verification_status": validate_verification(verification),
        "http_status": http_status,
        "content_type": content_type,
        "redirect_url": redirect_url,
        "error": error,
    }


def make_discovered_path(
    path: str,
    source: str,
    verification: str = "discovered",
    http_status: int | None = None,
    error: str | None = None,
) -> dict:
    """A path discovered on the target domain.

    Paths are distinct from URLs: a path is relative to the target
    origin and does not carry scheme/host information.
    """
    path = validate_path(path)
    return {
        "path": path,
        "discovery_source": str(source) if source else "unknown",
        "verification_status": validate_verification(verification),
        "http_status": http_status,
        "error": error,
    }


def make_api_endpoint(
    url: str,
    source: str,
    category: str = "REST",
    confidence: str = "low",
    score: int = 0,
    evidence: Any = None,
    verified: bool = False,
) -> dict:
    """An API endpoint discovered passively.

    ``verified`` is always ``False`` unless an explicit, authorised
    GET request was made (which RRI does not do by default for API
    endpoints).  This field exists to make the separation between
    *discovery* and *active probing* unambiguous in the data.
    """
    url = validate_url(url)
    return {
        "url": url,
        "discovery_source": str(source) if source else "unknown",
        "category": str(category) if category else "REST",
        "confidence": validate_confidence(confidence),
        "score": max(0, min(100, int(score) if isinstance(score, (int, float)) else 0)),
        "evidence": truncate_evidence(evidence),
        "verified": bool(verified),
    }


def make_technology(
    name: str,
    category: str,
    confidence: str,
    score: int = 0,
    evidence: Any = None,
    detection_source: str = "unknown",
) -> dict:
    """A detected technology (web server, framework, CMS, etc.)."""
    return {
        "name": str(name) if name else "unknown",
        "category": str(category) if category else "unknown",
        "confidence": validate_confidence(confidence),
        "score": max(0, min(100, int(score) if isinstance(score, (int, float)) else 0)),
        "evidence": truncate_evidence(evidence),
        "detection_source": str(detection_source) if detection_source else "unknown",
    }


def make_dns_record(
    record_type: str,
    hostname: str,
    values: list[str],
    source: str = "dns_lookup",
    error: str | None = None,
) -> dict:
    """A DNS record gathered for information purposes.

    This is **separate** from the SafeDNSResolver used for connection
    safety.  DNS information gathering is passive observation only --
    the records here are not used to authorise or route any request.
    """
    if not isinstance(values, list):
        values = [str(values)] if values else []

    values = [str(v) for v in values if v is not None]

    return {
        "record_type": str(record_type).upper() if record_type else "UNKNOWN",
        "hostname": str(hostname) if hostname else "unknown",
        "values": values,
        "discovery_source": str(source) if source else "dns_lookup",
        "error": error,
    }


def make_http_info(
    url: str,
    http_status: int | None = None,
    headers: dict | None = None,
    content_type: str | None = None,
    content_length: int | None = None,
    server: str | None = None,
    redirect_count: int = 0,
    final_url: str | None = None,
) -> dict:
    """Structured HTTP response information."""
    url = validate_url(url)
    if headers is None:
        headers = {}
    if not isinstance(headers, dict):
        headers = {}

    return {
        "url": url,
        "http_status": http_status,
        "headers": headers,
        "content_type": content_type,
        "content_length": content_length,
        "server": server,
        "redirect_count": max(0, int(redirect_count) if isinstance(redirect_count, (int, float)) else 0),
        "final_url": final_url,
    }


def make_tls_info(
    hostname: str,
    tls_version: str | None = None,
    cipher_suite: str | None = None,
    cert_valid: bool | None = None,
    cert_hostname_valid: bool | None = None,
    cert_not_before: str | None = None,
    cert_not_after: str | None = None,
    cert_issuer: str | None = None,
    cert_subject: str | None = None,
    error: str | None = None,
) -> dict:
    """TLS/SSL connection and certificate information.

    All fields except ``hostname`` are optional because the TLS
    handshake may fail before they are available.  ``cert_valid``
    and ``cert_hostname_valid`` are ``None`` when the certificate
    could not be inspected.
    """
    return {
        "hostname": str(hostname) if hostname else "unknown",
        "tls_version": tls_version,
        "cipher_suite": cipher_suite,
        "cert_valid": cert_valid,
        "cert_hostname_valid": cert_hostname_valid,
        "cert_not_before": cert_not_before,
        "cert_not_after": cert_not_after,
        "cert_issuer": cert_issuer,
        "cert_subject": cert_subject,
        "error": error,
    }


def make_security_finding(
    finding_id: str,
    title: str,
    category: str,
    severity: str,
    confidence: str,
    evidence: Any,
    description: str,
    recommendation: str,
    affected_url: str | None = None,
    detection_method: str = "passive",
) -> dict:
    """A passive security observation.

    Every finding includes:
      * ``title`` -- short human-readable label
      * ``severity`` -- critical / high / medium / low / info
      * ``confidence`` -- high / medium / low
      * ``evidence`` -- what was observed (never a guess)
      * ``affected_url`` -- the URL where the observation was made
      * ``recommendation`` -- actionable next step
      * ``detection_method`` -- how it was detected (always passive)
    """
    return {
        "id": str(finding_id) if finding_id else "unknown",
        "title": str(title) if title else "unknown",
        "category": str(category) if category else "unknown",
        "severity": validate_severity(severity),
        "confidence": validate_confidence(confidence),
        "evidence": truncate_evidence(evidence),
        "description": str(description) if description else "",
        "recommendation": str(recommendation) if recommendation else "",
        "affected_url": affected_url,
        "detection_method": str(detection_method) if detection_method else "passive",
    }


def make_correlation(
    corr_type: str,
    title: str,
    severity: str,
    confidence: str,
    entities: dict,
    evidence: Any,
    description: str,
    caveat: str = "",
) -> dict:
    """A correlation between two or more recon results."""
    if not isinstance(entities, dict):
        entities = {}

    return {
        "type": str(corr_type) if corr_type else "unknown",
        "title": str(title) if title else "unknown",
        "severity": validate_severity(severity),
        "confidence": validate_confidence(confidence),
        "entities": entities,
        "evidence": truncate_evidence(evidence),
        "description": str(description) if description else "",
        "caveat": str(caveat) if caveat else "",
    }


def make_js_analysis(
    script_url: str,
    source: str = "external_javascript",
    api_paths: list[str] | None = None,
    internal_routes: list[str] | None = None,
    urls: list[str] | None = None,
    source_map_refs: list[str] | None = None,
    config_refs: list[str] | None = None,
    error: str | None = None,
) -> dict:
    """Results of analysing a single JavaScript file.

    All list fields default to empty -- a JS file may contain none,
    some, or all of these categories.  Nothing here implies that any
    endpoint was probed.
    """
    def _clean(items):
        if not isinstance(items, list):
            return []
        return [str(i) for i in items if i is not None]

    return {
        "script_url": str(script_url) if script_url else "",
        "discovery_source": str(source) if source else "external_javascript",
        "api_paths": _clean(api_paths),
        "internal_routes": _clean(internal_routes),
        "urls": _clean(urls),
        "source_map_refs": _clean(source_map_refs),
        "config_refs": _clean(config_refs),
        "error": error,
    }


def make_module_result(
    module_name: str,
    status: str = "completed",
    target: str = "",
    items_key: str = "",
    items: list | None = None,
    error: str | None = None,
    **extra,
) -> dict:
    """Standard envelope for every module's return value.

    Every recon module returns a dict with at least:
      * ``status`` -- completed / error / blocked
      * ``target`` -- the URL that was analysed
      * ``error`` -- None on success, a message on failure

    Additional module-specific fields are passed via ``**extra``.
    """
    result: dict[str, Any] = {
        "status": status,
        "target": str(target) if target else "",
        "error": error,
    }

    if items_key:
        result[items_key] = items if isinstance(items, list) else []
        result[f"{items_key.removesuffix('s')}_count" if items_key.endswith("s") else f"{items_key}_count"] = (
            len(result[items_key])
        )

    result.update(extra)

    return result
