"""Tests for modules/path_discovery.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.scope import ScopeEngine
from modules.path_discovery import PathDiscovery, PathExtractor


class TestPathExtractor:
    def test_extracts_href(self):
        parser = PathExtractor()
        parser.feed('<a href="/page">Link</a>')
        parser.close()
        assert "/page" in parser.references

    def test_extracts_src(self):
        parser = PathExtractor()
        parser.feed('<script src="/app.js"></script>')
        parser.close()
        assert "/app.js" in parser.references

    def test_extracts_action(self):
        parser = PathExtractor()
        parser.feed('<form action="/submit">')
        parser.close()
        assert "/submit" in parser.references

    def test_extracts_data_url(self):
        parser = PathExtractor()
        parser.feed('<div data-url="/api/data"></div>')
        parser.close()
        assert "/api/data" in parser.references


class TestPathDiscoveryInit:
    def test_defaults(self):
        engine = MagicMock()
        pd = PathDiscovery(engine)
        assert pd.max_script_files == 10

    def test_invalid_script_count(self):
        engine = MagicMock()
        with pytest.raises(ValueError):
            PathDiscovery(engine, max_script_files=-1)

    def test_invalid_script_count_too_high(self):
        engine = MagicMock()
        with pytest.raises(ValueError):
            PathDiscovery(engine, max_script_files=100)


class TestPathDiscoveryScan:
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
        pd = PathDiscovery(engine)
        result = asyncio.run(pd.scan(""))
        assert result["status"] == "error"

    def test_blocked_page_url(self):
        scope = MagicMock()
        scope.check = MagicMock(return_value=(False, "Out of scope"))
        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value={
            "status": "completed", "url": "https://evil.com/", "http_status": 200,
            "headers": {}, "body": b"<html></html>",
        })

        pd = PathDiscovery(engine)
        result = asyncio.run(pd.scan("https://evil.com/"))

        assert result["status"] == "blocked"

    def test_extracts_paths_from_html(self):
        scope = ScopeEngine("https://example.invalid/")
        body = b'<html><a href="/about">About</a><a href="/contact">Contact</a></html>'

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://example.invalid/", body))

        pd = PathDiscovery(engine)
        result = asyncio.run(pd.scan("https://example.invalid/"))

        paths = [p["path"] for p in result["discovered_paths"]]
        assert "/about" in paths
        assert "/contact" in paths

    def test_extracts_paths_from_inline_js(self):
        scope = ScopeEngine("https://example.invalid/")
        body = b'<html><script>fetch("/api/users"); navigate("/dashboard");</script></html>'

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://example.invalid/", body))

        pd = PathDiscovery(engine)
        result = asyncio.run(pd.scan("https://example.invalid/"))

        paths = [p["path"] for p in result["discovered_paths"]]
        assert "/api/users" in paths
        assert "/dashboard" in paths

    def test_extracts_paths_from_external_js(self):
        scope = ScopeEngine("https://example.invalid/")
        page_body = b'<html><script src="/app.js"></script></html>'
        js_body = b'var r = "/settings"; var x = "/profile";'

        def fetch_side_effect(url):
            if url == "https://example.invalid/":
                return self._make_response(url, page_body)
            if url == "https://example.invalid/app.js":
                return self._make_response(url, js_body)
            return {"status": "error", "url": url, "error": "Not found"}

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(side_effect=fetch_side_effect)

        pd = PathDiscovery(engine)
        result = asyncio.run(pd.scan("https://example.invalid/"))

        paths = [p["path"] for p in result["discovered_paths"]]
        assert "/settings" in paths
        assert "/profile" in paths

    def test_rejects_external_paths(self):
        scope = ScopeEngine("https://example.invalid/")
        body = b'<html><a href="https://other.com/page">External</a><a href="/internal">Internal</a></html>'

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://example.invalid/", body))

        pd = PathDiscovery(engine)
        result = asyncio.run(pd.scan("https://example.invalid/"))

        paths = [p["path"] for p in result["discovered_paths"]]
        assert "/internal" in paths
        assert not any("other.com" in p for p in paths)

    def test_rejects_subdomain_paths(self):
        scope = ScopeEngine("https://example.invalid/")
        body = b'<html><a href="https://sub.example.invalid/page">Sub</a></html>'

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://example.invalid/", body))

        pd = PathDiscovery(engine)
        result = asyncio.run(pd.scan("https://example.invalid/"))

        paths = [p["path"] for p in result["discovered_paths"]]
        assert not any("sub.example.invalid" in p for p in paths)

    def test_all_paths_have_source(self):
        scope = ScopeEngine("https://example.invalid/")
        body = b'<html><a href="/about">About</a><script>var p = "/api";</script></html>'

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://example.invalid/", body))

        pd = PathDiscovery(engine)
        result = asyncio.run(pd.scan("https://example.invalid/"))

        for p in result["discovered_paths"]:
            assert "discovery_source" in p
            assert p["discovery_source"] in ("html", "inline_javascript", "external_javascript", "crawler")

    def test_all_paths_have_verification_status(self):
        scope = ScopeEngine("https://example.invalid/")
        body = b'<html><a href="/page">Page</a></html>'

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://example.invalid/", body))

        pd = PathDiscovery(engine)
        result = asyncio.run(pd.scan("https://example.invalid/"))

        for p in result["discovered_paths"]:
            assert p["verification_status"] in ("discovered", "tested", "confirmed", "failed")

    def test_wordlist_disabled_by_default(self):
        scope = ScopeEngine("https://example.invalid/")
        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://example.invalid/", b"<html></html>"))

        pd = PathDiscovery(engine)
        result = asyncio.run(pd.scan("https://example.invalid/"))

        assert result["wordlist_enabled"] is False
        assert result["tested_paths"] == []

    def test_wordlist_enabled_tests_paths(self):
        scope = ScopeEngine("https://example.invalid/")

        def fetch_side_effect(url):
            if url == "https://example.invalid/":
                return self._make_response(url, b"<html></html>")
            if url == "https://example.invalid/admin":
                return self._make_response(url, b"<html>Admin</html>", 200)
            return {"status": "completed", "url": url, "http_status": 404, "headers": {}, "body": b""}

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(side_effect=fetch_side_effect)

        pd = PathDiscovery(engine, wordlist_delay=0)
        result = asyncio.run(pd.scan("https://example.invalid/", wordlist=["admin", "secret"]))

        assert result["wordlist_enabled"] is True
        assert len(result["tested_paths"]) == 2
        confirmed = [p["path"] for p in result["confirmed_paths"]]
        assert "/admin" in confirmed

    def test_wordlist_respects_rate_limiting(self):
        scope = ScopeEngine("https://example.invalid/")

        def fetch_side_effect(url):
            if url == "https://example.invalid/":
                return self._make_response(url, b"<html></html>")
            return {"status": "completed", "url": url, "http_status": 404, "headers": {}, "body": b""}

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(side_effect=fetch_side_effect)

        pd = PathDiscovery(engine, wordlist_delay=0.3)
        import time
        start = time.monotonic()
        result = asyncio.run(pd.scan("https://example.invalid/", wordlist=["a", "b", "c"]))
        elapsed = time.monotonic() - start

        assert result["wordlist_enabled"] is True
        assert len(result["tested_paths"]) == 3
        assert elapsed >= 0.6

    def test_wordlist_delay_validation(self):
        engine = MagicMock()
        with pytest.raises(ValueError):
            PathDiscovery(engine, wordlist_delay=-1)
        with pytest.raises(ValueError):
            PathDiscovery(engine, wordlist_delay=20)
        with pytest.raises(ValueError):
            PathDiscovery(engine, wordlist_delay=True)

    def test_merge_crawl_results(self):
        scope = ScopeEngine("https://example.invalid/")
        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://example.invalid/", b"<html></html>"))

        crawl_results = {
            "discovered_paths": [
                {"path": "/crawled1", "verification_status": "confirmed", "http_status": 200},
                {"path": "/crawled2", "verification_status": "discovered"},
            ]
        }

        pd = PathDiscovery(engine)
        result = asyncio.run(pd.scan("https://example.invalid/", crawl_results=crawl_results))

        paths = [p["path"] for p in result["discovered_paths"]]
        assert "/crawled1" in paths
        assert "/crawled2" in paths

    def test_fetch_failure_returns_error(self):
        scope = ScopeEngine("https://example.invalid/")
        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value={
            "status": "network_error", "url": "https://example.invalid/", "error": "Timeout",
        })

        pd = PathDiscovery(engine)
        result = asyncio.run(pd.scan("https://example.invalid/"))

        assert result["status"] == "network_error"
        assert "Timeout" in result["error"]

    def test_paths_deduplicated(self):
        scope = ScopeEngine("https://example.invalid/")
        body = b'<html><a href="/about">A</a><a href="/about">B</a><script>var x = "/about";</script></html>'

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://example.invalid/", body))

        pd = PathDiscovery(engine)
        result = asyncio.run(pd.scan("https://example.invalid/"))

        paths = [p["path"] for p in result["discovered_paths"]]
        assert paths.count("/about") == 1
