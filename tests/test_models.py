"""Tests for core/models.py -- unified data models."""

import pytest

from core.models import (
    CONFIDENCE_LEVELS,
    MAX_EVIDENCE_LENGTH,
    MAX_URL_LENGTH,
    SEVERITY_LEVELS,
    VERIFICATION_STATUSES,
    make_api_endpoint,
    make_correlation,
    make_discovered_path,
    make_discovered_url,
    make_dns_record,
    make_http_info,
    make_js_analysis,
    make_module_result,
    make_security_finding,
    make_technology,
    make_tls_info,
    origin_from_url,
    path_from_url,
    validate_confidence,
    validate_path,
    validate_severity,
    validate_url,
    validate_verification,
    truncate_evidence,
)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

class TestValidateUrl:
    def test_valid_url(self):
        assert validate_url("https://example.com/path") == "https://example.com/path"

    def test_strips_whitespace(self):
        assert validate_url("  https://example.com  ") == "https://example.com"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            validate_url("")

    def test_rejects_none(self):
        with pytest.raises(ValueError):
            validate_url(None)

    def test_rejects_non_string(self):
        with pytest.raises(ValueError):
            validate_url(123)

    def test_rejects_control_chars(self):
        with pytest.raises(ValueError):
            validate_url("https://example.com\x00")

    def test_rejects_backslashes(self):
        with pytest.raises(ValueError):
            validate_url("https://example.com\\path")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError):
            validate_url("https://example.com/" + "a" * MAX_URL_LENGTH)


class TestValidatePath:
    def test_valid_path(self):
        assert validate_path("/api/v1/users") == "/api/v1/users"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            validate_path("")

    def test_rejects_none(self):
        with pytest.raises(ValueError):
            validate_path(None)

    def test_rejects_control_chars(self):
        with pytest.raises(ValueError):
            validate_path("/path\x01")


class TestValidateSeverity:
    @pytest.mark.parametrize("level", SEVERITY_LEVELS)
    def test_valid_levels(self, level):
        assert validate_severity(level) == level

    def test_case_insensitive(self):
        assert validate_severity("HIGH") == "high"

    def test_invalid_defaults_to_info(self):
        assert validate_severity("bogus") == "info"

    def test_non_string_defaults_to_info(self):
        assert validate_severity(42) == "info"


class TestValidateConfidence:
    @pytest.mark.parametrize("level", CONFIDENCE_LEVELS)
    def test_valid_levels(self, level):
        assert validate_confidence(level) == level

    def test_case_insensitive(self):
        assert validate_confidence("MEDIUM") == "medium"

    def test_invalid_defaults_to_low(self):
        assert validate_confidence("bogus") == "low"


class TestValidateVerification:
    @pytest.mark.parametrize("status", VERIFICATION_STATUSES)
    def test_valid_statuses(self, status):
        assert validate_verification(status) == status

    def test_invalid_defaults_to_discovered(self):
        assert validate_verification("bogus") == "discovered"


class TestTruncateEvidence:
    def test_short_value(self):
        assert truncate_evidence("short") == "short"

    def test_long_value_truncated(self):
        result = truncate_evidence("x" * (MAX_EVIDENCE_LENGTH + 100))
        assert len(result) == MAX_EVIDENCE_LENGTH

    def test_none_becomes_empty(self):
        assert truncate_evidence(None) == ""

    def test_non_string_converted(self):
        assert truncate_evidence(42) == "42"


# ---------------------------------------------------------------------------
# origin_from_url / path_from_url
# ---------------------------------------------------------------------------

class TestOriginFromUrl:
    def test_https_default_port(self):
        assert origin_from_url("https://example.com/path") == ("https", "example.com", 443)

    def test_http_default_port(self):
        assert origin_from_url("http://example.com/path") == ("http", "example.com", 80)

    def test_explicit_port(self):
        assert origin_from_url("https://example.com:8443/") == ("https", "example.com", 8443)

    def test_idna_normalization(self):
        assert origin_from_url("https://EXAMPLE.com/") == ("https", "example.com", 443)

    def test_rejects_credentials(self):
        assert origin_from_url("https://user:pass@example.com/") is None

    def test_rejects_non_http(self):
        assert origin_from_url("ftp://example.com/") is None

    def test_rejects_empty(self):
        assert origin_from_url("") is None

    def test_rejects_none(self):
        assert origin_from_url(None) is None

    def test_rejects_whitespace(self):
        assert origin_from_url(" https://example.com/ ") is None


class TestPathFromUrl:
    def test_normal_path(self):
        assert path_from_url("https://example.com/api/v1") == "/api/v1"

    def test_root_path(self):
        assert path_from_url("https://example.com") == "/"

    def test_rejects_empty(self):
        assert path_from_url("") is None

    def test_rejects_none(self):
        assert path_from_url(None) is None


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------

class TestMakeDiscoveredUrl:
    def test_defaults(self):
        result = make_discovered_url("https://example.com/page", "html")
        assert result["url"] == "https://example.com/page"
        assert result["discovery_source"] == "html"
        assert result["verification_status"] == "discovered"
        assert result["http_status"] is None
        assert result["error"] is None

    def test_tested_status(self):
        result = make_discovered_url(
            "https://example.com/page", "crawler",
            verification="tested", http_status=200,
        )
        assert result["verification_status"] == "tested"
        assert result["http_status"] == 200

    def test_failed_status(self):
        result = make_discovered_url(
            "https://example.com/page", "crawler",
            verification="failed", error="timeout",
        )
        assert result["verification_status"] == "failed"
        assert result["error"] == "timeout"

    def test_invalid_verification_defaults(self):
        result = make_discovered_url("https://example.com/", "html", verification="bogus")
        assert result["verification_status"] == "discovered"

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError):
            make_discovered_url("", "html")


class TestMakeDiscoveredPath:
    def test_defaults(self):
        result = make_discovered_path("/api/users", "javascript")
        assert result["path"] == "/api/users"
        assert result["discovery_source"] == "javascript"
        assert result["verification_status"] == "discovered"

    def test_confirmed(self):
        result = make_discovered_path("/admin", "wordlist", verification="confirmed", http_status=200)
        assert result["verification_status"] == "confirmed"
        assert result["http_status"] == 200

    def test_invalid_path_raises(self):
        with pytest.raises(ValueError):
            make_discovered_path("", "html")


class TestMakeApiEndpoint:
    def test_defaults(self):
        result = make_api_endpoint("https://example.com/api/v1/users", "html")
        assert result["url"] == "https://example.com/api/v1/users"
        assert result["discovery_source"] == "html"
        assert result["category"] == "REST"
        assert result["confidence"] == "low"
        assert result["score"] == 0
        assert result["verified"] is False

    def test_score_clamped(self):
        assert make_api_endpoint("https://example.com/", "html", score=150)["score"] == 100
        assert make_api_endpoint("https://example.com/", "html", score=-10)["score"] == 0

    def test_verified_defaults_false(self):
        result = make_api_endpoint("https://example.com/", "html")
        assert result["verified"] is False

    def test_evidence_truncated(self):
        result = make_api_endpoint("https://example.com/", "html", evidence="x" * 600)
        assert len(result["evidence"]) == MAX_EVIDENCE_LENGTH


class TestMakeTechnology:
    def test_defaults(self):
        result = make_technology(
            "Nginx", "Web Server", "high", 85,
            evidence="nginx in Server header",
            detection_source="server header",
        )
        assert result["name"] == "Nginx"
        assert result["category"] == "Web Server"
        assert result["confidence"] == "high"
        assert result["score"] == 85
        assert result["detection_source"] == "server header"
        assert result["evidence"] == "nginx in Server header"

    def test_score_clamped(self):
        assert make_technology("X", "Y", "low", 200)["score"] == 100
        assert make_technology("X", "Y", "low", -5)["score"] == 0


class TestMakeDnsRecord:
    def test_valid_record(self):
        result = make_dns_record("A", "example.com", ["1.2.3.4"])
        assert result["record_type"] == "A"
        assert result["hostname"] == "example.com"
        assert result["values"] == ["1.2.3.4"]

    def test_single_value_converted_to_list(self):
        result = make_dns_record("MX", "example.com", "mail.example.com")
        assert result["values"] == ["mail.example.com"]

    def test_none_values_filtered(self):
        result = make_dns_record("A", "example.com", [None, "1.2.3.4", None])
        assert result["values"] == ["1.2.3.4"]

    def test_error_field(self):
        result = make_dns_record("AAAA", "example.com", [], error="No AAAA record")
        assert result["error"] == "No AAAA record"
        assert result["values"] == []


class TestMakeHttpInfo:
    def test_defaults(self):
        result = make_http_info("https://example.com/")
        assert result["url"] == "https://example.com/"
        assert result["http_status"] is None
        assert result["headers"] == {}
        assert result["redirect_count"] == 0

    def test_with_values(self):
        result = make_http_info(
            "https://example.com/",
            http_status=200,
            headers={"server": "nginx"},
            content_type="text/html",
            content_length=1024,
            server="nginx",
            redirect_count=2,
            final_url="https://example.com/final",
        )
        assert result["http_status"] == 200
        assert result["headers"] == {"server": "nginx"}
        assert result["content_type"] == "text/html"
        assert result["content_length"] == 1024
        assert result["server"] == "nginx"
        assert result["redirect_count"] == 2
        assert result["final_url"] == "https://example.com/final"

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError):
            make_http_info("")


class TestMakeTlsInfo:
    def test_defaults(self):
        result = make_tls_info("example.com")
        assert result["hostname"] == "example.com"
        assert result["tls_version"] is None
        assert result["cert_valid"] is None
        assert result["cert_hostname_valid"] is None
        assert result["error"] is None

    def test_with_values(self):
        result = make_tls_info(
            "example.com",
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            cert_valid=True,
            cert_hostname_valid=True,
            cert_not_before="2025-01-01T00:00:00Z",
            cert_not_after="2026-01-01T00:00:00Z",
            cert_issuer="Let's Encrypt",
            cert_subject="example.com",
        )
        assert result["tls_version"] == "TLSv1.3"
        assert result["cert_valid"] is True
        assert result["cert_hostname_valid"] is True
        assert result["cert_issuer"] == "Let's Encrypt"


class TestMakeSecurityFinding:
    def test_full_finding(self):
        result = make_security_finding(
            "HSTS_MISSING",
            "Missing HSTS",
            "Transport Security",
            "medium",
            "medium",
            None,
            "No HSTS header detected.",
            "Configure HSTS.",
            affected_url="https://example.com/",
        )
        assert result["id"] == "HSTS_MISSING"
        assert result["title"] == "Missing HSTS"
        assert result["severity"] == "medium"
        assert result["confidence"] == "medium"
        assert result["affected_url"] == "https://example.com/"
        assert result["detection_method"] == "passive"

    def test_severity_normalised(self):
        result = make_security_finding("X", "Y", "Z", "CRITICAL", "HIGH", "e", "d", "r")
        assert result["severity"] == "critical"
        assert result["confidence"] == "high"

    def test_invalid_severity_defaults_to_info(self):
        result = make_security_finding("X", "Y", "Z", "bogus", "low", "e", "d", "r")
        assert result["severity"] == "info"


class TestMakeCorrelation:
    def test_defaults(self):
        result = make_correlation(
            "endpoint_security_overlap",
            "Test correlation",
            "info",
            "low",
            {"a": "b"},
            "evidence text",
            "description",
        )
        assert result["type"] == "endpoint_security_overlap"
        assert result["severity"] == "info"
        assert result["entities"] == {"a": "b"}
        assert result["caveat"] == ""

    def test_entities_non_dict_converted(self):
        result = make_correlation("t", "title", "info", "low", "not a dict", "e", "d")
        assert result["entities"] == {}


class TestMakeJsAnalysis:
    def test_defaults(self):
        result = make_js_analysis("https://example.com/app.js")
        assert result["script_url"] == "https://example.com/app.js"
        assert result["api_paths"] == []
        assert result["internal_routes"] == []
        assert result["urls"] == []
        assert result["source_map_refs"] == []
        assert result["config_refs"] == []
        assert result["error"] is None

    def test_with_values(self):
        result = make_js_analysis(
            "https://example.com/app.js",
            api_paths=["/api/users", "/api/posts"],
            internal_routes=["/dashboard", "/settings"],
            urls=["https://example.com/redirect"],
            source_map_refs=["app.js.map"],
            config_refs=["API_KEY"],
        )
        assert result["api_paths"] == ["/api/users", "/api/posts"]
        assert result["internal_routes"] == ["/dashboard", "/settings"]

    def test_none_items_filtered(self):
        result = make_js_analysis(
            "https://example.com/app.js",
            api_paths=[None, "/api", None],
        )
        assert result["api_paths"] == ["/api"]


class TestMakeModuleResult:
    def test_defaults(self):
        result = make_module_result("technology", target="https://example.com/")
        assert result["status"] == "completed"
        assert result["target"] == "https://example.com/"
        assert result["error"] is None

    def test_with_items(self):
        result = make_module_result(
            "path_discovery",
            target="https://example.com/",
            items_key="paths",
            items=[{"path": "/admin"}],
        )
        assert result["paths"] == [{"path": "/admin"}]
        assert result["path_count"] == 1

    def test_with_extra_fields(self):
        result = make_module_result(
            "dns_info",
            target="https://example.com/",
            records=[{"record_type": "A"}],
            hostname="example.com",
        )
        assert result["records"] == [{"record_type": "A"}]
        assert result["hostname"] == "example.com"

    def test_error_status(self):
        result = make_module_result(
            "tls_analysis",
            status="error",
            target="https://example.com/",
            error="Connection failed",
        )
        assert result["status"] == "error"
        assert result["error"] == "Connection failed"

    def test_items_non_list_defaults(self):
        result = make_module_result(
            "test",
            items_key="things",
            items="not a list",
        )
        assert result["things"] == []


# ---------------------------------------------------------------------------
# Immutability / fresh-dict check
# ---------------------------------------------------------------------------

class TestFreshDicts:
    def test_discovered_url_is_independent(self):
        a = make_discovered_url("https://example.com/a", "html")
        b = make_discovered_url("https://example.com/b", "html")
        a["url"] = "modified"
        assert b["url"] == "https://example.com/b"

    def test_js_analysis_lists_are_independent(self):
        a = make_js_analysis("https://example.com/a.js", api_paths=["/api"])
        b = make_js_analysis("https://example.com/b.js")
        a["api_paths"].append("/new")
        assert b["api_paths"] == []
