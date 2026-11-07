"""Tests for modules/js_analysis.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.scope import ScopeEngine
from modules.js_analysis import JSAnalyzer


class TestJSAnalyzerInit:
    def test_defaults(self):
        engine = MagicMock()
        ja = JSAnalyzer(engine)
        assert ja.max_script_files == 10

    def test_custom_limit(self):
        engine = MagicMock()
        ja = JSAnalyzer(engine, max_script_files=20)
        assert ja.max_script_files == 20

    def test_invalid_limit_negative(self):
        engine = MagicMock()
        with pytest.raises(ValueError):
            JSAnalyzer(engine, max_script_files=-1)

    def test_invalid_limit_too_high(self):
        engine = MagicMock()
        with pytest.raises(ValueError):
            JSAnalyzer(engine, max_script_files=100)

    def test_invalid_limit_bool(self):
        engine = MagicMock()
        with pytest.raises(ValueError):
            JSAnalyzer(engine, max_script_files=True)


class TestPatternExtraction:
    def setup_method(self):
        self.engine = MagicMock()
        self.ja = JSAnalyzer(self.engine)

    def test_extract_api_paths(self):
        content = 'fetch("/api/users"); var x = "/api/v1/products";'
        result = self.ja._extract_api_paths(content)
        assert "/api/users" in result
        assert "/api/v1/products" in result

    def test_extract_api_paths_dedup(self):
        content = 'fetch("/api/users"); fetch("/api/users");'
        result = self.ja._extract_api_paths(content)
        assert len(result) == 1

    def test_extract_routes(self):
        content = '{path: "/dashboard", route: "/settings"}'
        result = self.ja._extract_routes(content)
        assert "/dashboard" in result
        assert "/settings" in result

    def test_extract_urls(self):
        content = 'var a = "https://example.invalid/api"; var b = "http://other.com/page";'
        result = self.ja._extract_urls(content)
        assert "https://example.invalid/api" in result
        assert "http://other.com/page" in result

    def test_extract_source_map(self):
        content = '//# sourceMappingURL=app.js.map'
        result = self.ja._extract_source_map_refs(content)
        assert "app.js.map" in result

    def test_extract_config_refs(self):
        content = 'var config = {api_key: "sk_test_12345", token: "abc123def"};'
        result = self.ja._extract_config_refs(content)
        assert "api_key=[REDACTED]" in result
        assert "token=[REDACTED]" in result

    def test_no_api_paths_in_plain_text(self):
        result = self.ja._extract_api_paths("hello world")
        assert result == []

    def test_no_routes_in_plain_text(self):
        result = self.ja._extract_routes("no routes here")
        assert result == []


class TestJSAnalyzerScan:
    def _make_response(self, url, body=b"<html></html>", status=200):
        return {
            "status": "completed",
            "url": url,
            "http_status": status,
            "headers": {},
            "body": body,
        }

    def test_empty_target(self):
        engine = MagicMock()
        ja = JSAnalyzer(engine)
        result = asyncio.run(ja.scan(""))
        assert result["status"] == "error"

    def test_blocked_page_url(self):
        scope = MagicMock()
        scope.check = MagicMock(return_value=(False, "Out of scope"))
        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://evil.com/"))

        ja = JSAnalyzer(engine)
        result = asyncio.run(ja.scan("https://evil.com/"))
        assert result["status"] == "blocked"

    def test_analyzes_inline_scripts(self):
        scope = ScopeEngine("https://example.invalid/")
        body = b'<html><script>fetch("/api/users"); var routes = [{path: "/dashboard"}];</script></html>'

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://example.invalid/", body))

        ja = JSAnalyzer(engine)
        result = asyncio.run(ja.scan("https://example.invalid/"))

        assert result["status"] == "completed"
        assert "/api/users" in result["all_api_paths"]
        assert "/dashboard" in result["all_routes"]
        assert result["inline_scripts_analyzed"] == 1

    def test_analyzes_external_scripts(self):
        scope = ScopeEngine("https://example.invalid/")
        page_body = b'<html><script src="/app.js"></script></html>'
        js_body = b'var config = {api_key: "sk_test_123"}; var x = "/api/products";'

        def fetch_side_effect(url):
            if url == "https://example.invalid/":
                return self._make_response(url, page_body)
            if url == "https://example.invalid/app.js":
                return self._make_response(url, js_body)
            return {"status": "error", "url": url, "error": "Not found"}

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(side_effect=fetch_side_effect)

        ja = JSAnalyzer(engine)
        result = asyncio.run(ja.scan("https://example.invalid/"))

        assert result["script_files_fetched"] == 1
        assert "/api/products" in result["all_api_paths"]
        assert "api_key=[REDACTED]" in result["all_config_refs"]

    def test_rejects_out_of_scope_scripts(self):
        scope = ScopeEngine("https://example.invalid/")
        page_body = b'<html><script src="https://other.com/evil.js"></script></html>'

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://example.invalid/", page_body))

        ja = JSAnalyzer(engine)
        result = asyncio.run(ja.scan("https://example.invalid/"))

        assert result["script_files_discovered"] == 0
        assert result["script_files_fetched"] == 0

    def test_handles_fetch_failure(self):
        scope = ScopeEngine("https://example.invalid/")
        page_body = b'<html><script src="/app.js"></script></html>'

        def fetch_side_effect(url):
            if url == "https://example.invalid/":
                return self._make_response(url, page_body)
            return {"status": "network_error", "url": url, "error": "Timeout"}

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(side_effect=fetch_side_effect)

        ja = JSAnalyzer(engine)
        result = asyncio.run(ja.scan("https://example.invalid/"))

        assert result["script_files_skipped"] == 1
        assert len(result["analyzed_scripts"]) >= 1

    def test_extract_urls_from_js(self):
        scope = ScopeEngine("https://example.invalid/")
        body = b'<html><script>var a = "https://example.invalid/page";</script></html>'

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://example.invalid/", body))

        ja = JSAnalyzer(engine)
        result = asyncio.run(ja.scan("https://example.invalid/"))

        assert "https://example.invalid/page" in result["all_urls"]

    def test_source_map_refs(self):
        scope = ScopeEngine("https://example.invalid/")
        body = b'<html><script>//# sourceMappingURL=bundle.js.map</script></html>'

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://example.invalid/", body))

        ja = JSAnalyzer(engine)
        result = asyncio.run(ja.scan("https://example.invalid/"))

        assert "bundle.js.map" in result["all_source_map_refs"]

    def test_no_scripts(self):
        scope = ScopeEngine("https://example.invalid/")
        body = b"<html><body>No scripts here</body></html>"

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://example.invalid/", body))

        ja = JSAnalyzer(engine)
        result = asyncio.run(ja.scan("https://example.invalid/"))

        assert result["inline_scripts_analyzed"] == 0
        assert result["script_files_discovered"] == 0
        assert result["all_api_paths"] == []

    def test_fetch_failure_returns_error(self):
        scope = ScopeEngine("https://example.invalid/")
        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value={
            "status": "network_error", "url": "https://example.invalid/", "error": "Timeout",
        })

        ja = JSAnalyzer(engine)
        result = asyncio.run(ja.scan("https://example.invalid/"))

        assert result["status"] == "network_error"
        assert "Timeout" in result["error"]

    def test_respects_max_script_files(self):
        scope = ScopeEngine("https://example.invalid/")
        page_body = b'<html><script src="/a.js"></script><script src="/b.js"></script></html>'

        def fetch_side_effect(url):
            if url == "https://example.invalid/":
                return self._make_response(url, page_body)
            return self._make_response(url, b'var x = "/api/test";')

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(side_effect=fetch_side_effect)

        ja = JSAnalyzer(engine, max_script_files=1)
        result = asyncio.run(ja.scan("https://example.invalid/"))

        assert result["script_files_discovered"] == 1


class TestConfigRefRedaction:
    def setup_method(self):
        self.engine = MagicMock()
        self.ja = JSAnalyzer(self.engine)

    def test_api_key_value_is_redacted(self):
        content = 'var config = {api_key: "sk_test_12345"};'
        result = self.ja._extract_config_refs(content)
        assert "api_key=[REDACTED]" in result
        assert "sk_test_12345" not in result

    def test_token_value_is_redacted(self):
        content = 'var t = {token: "Bearer abc123"};'
        result = self.ja._extract_config_refs(content)
        assert "token=[REDACTED]" in result
        assert "Bearer abc123" not in result

    def test_password_value_is_redacted(self):
        content = 'var p = {password: "s3cr3t"};';
        result = self.ja._extract_config_refs(content)
        assert "password=[REDACTED]" in result
        assert "s3cr3t" not in result

    def test_secret_value_is_redacted(self):
        content = 'var s = {secret: "my_secret_value"};';
        result = self.ja._extract_config_refs(content)
        assert "secret=[REDACTED]" in result
        assert "my_secret_value" not in result

    def test_raw_values_never_in_results(self):
        content = 'var c = {api_key: "AKIAIOSFODNN7EXAMPLE", secret: "wJalrXUtnFEMI/K7MDENG"};';
        result = self.ja._extract_config_refs(content)
        joined = " ".join(result)
        assert "AKIAIOSFODNN7EXAMPLE" not in joined
        assert "wJalrXUtnFEMI" not in joined

    def test_redacted_in_full_scan_result(self):
        scope = ScopeEngine("https://example.invalid/")
        body = b'<html><script>var c = {api_key: "sk_test_123"};</script></html>'

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value={
            "status": "completed", "url": "https://example.invalid/",
            "http_status": 200, "headers": {}, "body": body,
        })

        ja = JSAnalyzer(engine)
        result = asyncio.run(ja.scan("https://example.invalid/"))

        config_joined = " ".join(result["all_config_refs"])
        assert "sk_test_123" not in config_joined
        assert "api_key=[REDACTED]" in config_joined
