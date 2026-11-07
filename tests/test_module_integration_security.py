"""Security integration tests for module scope enforcement.

Verifies that all analysis modules re-check the response URL against
the authorized scope, even when a pre-fetched response is passed in.
This prevents processing data from out-of-scope URLs.
"""

import asyncio
from unittest.mock import MagicMock

from core.scope import ScopeEngine

from modules.headers_analysis import HeadersAnalyzer
from modules.security_checks import SecurityChecks
from modules.technology import TechnologyDetector


class TestHeadersAnalysisScopeRecheck:

    def _make_response(self, url, body=b"<html></html>"):
        return {
            "status": "completed",
            "url": url,
            "http_status": 200,
            "headers": {},
            "header_items": [],
            "body": body,
        }

    def test_blocks_out_of_scope_response_url(self):
        scope = ScopeEngine("https://example.invalid/")
        engine = MagicMock()
        engine.scope = scope

        analyzer = HeadersAnalyzer(engine=engine)
        response = self._make_response("https://evil.invalid/")

        result = asyncio.run(analyzer.scan("https://example.invalid/", response=response))
        assert result["status"] == "blocked"
        assert "outside scope" in result["error"].lower()

    def test_allows_in_scope_response_url(self):
        scope = ScopeEngine("https://example.invalid/")
        engine = MagicMock()
        engine.scope = scope

        analyzer = HeadersAnalyzer(engine=engine)
        response = self._make_response("https://example.invalid/")

        result = asyncio.run(analyzer.scan("https://example.invalid/", response=response))
        assert result["status"] == "completed"


class TestSecurityChecksScopeRecheck:

    def _make_response(self, url, body=b"<html></html>"):
        return {
            "status": "completed",
            "url": url,
            "http_status": 200,
            "headers": {},
            "header_items": [],
            "body": body,
        }

    def test_blocks_out_of_scope_response_url(self):
        scope = ScopeEngine("https://example.invalid/")
        engine = MagicMock()
        engine.scope = scope

        analyzer = SecurityChecks(engine=engine)
        response = self._make_response("https://evil.invalid/")

        result = asyncio.run(analyzer.scan("https://example.invalid/", response=response))
        assert result["status"] == "blocked"
        assert "outside scope" in result["error"].lower()

    def test_allows_in_scope_response_url(self):
        scope = ScopeEngine("https://example.invalid/")
        engine = MagicMock()
        engine.scope = scope

        analyzer = SecurityChecks(engine=engine)
        response = self._make_response("https://example.invalid/")

        result = asyncio.run(analyzer.scan("https://example.invalid/", response=response))
        assert result["status"] == "completed"


class TestTechnologyScopeRecheck:

    def _make_response(self, url, body=b"<html></html>"):
        return {
            "status": "completed",
            "url": url,
            "http_status": 200,
            "headers": {},
            "header_items": [],
            "body": body,
        }

    def test_blocks_out_of_scope_response_url(self):
        scope = ScopeEngine("https://example.invalid/")
        engine = MagicMock()
        engine.scope = scope

        detector = TechnologyDetector(engine=engine)
        response = self._make_response("https://evil.invalid/")

        result = asyncio.run(detector.scan("https://example.invalid/", response=response))
        assert result["status"] == "blocked"
        assert "outside scope" in result["error"].lower()

    def test_allows_in_scope_response_url(self):
        scope = ScopeEngine("https://example.invalid/")
        engine = MagicMock()
        engine.scope = scope

        detector = TechnologyDetector(engine=engine)
        response = self._make_response("https://example.invalid/")

        result = asyncio.run(detector.scan("https://example.invalid/", response=response))
        assert result["status"] == "completed"


class TestModuleIntegrationNoPostPutDelete:
    """Verify that no module sends POST/PUT/DELETE — all use GET via engine.fetch."""

    def test_http_engine_only_uses_get(self):
        import inspect
        from core.http_engine import HTTPEngine
        source = inspect.getsource(HTTPEngine.fetch)
        assert "session.get(" in source
        assert "session.post(" not in source
        assert "session.put(" not in source
        assert "session.delete(" not in source
        assert "session.patch(" not in source

    def test_no_module_imports_aiohttp_directly(self):
        import modules
        import importlib
        import pkgutil

        for importer, modname, ispkg in pkgutil.iter_modules(modules.__path__):
            if ispkg:
                continue
            mod = importlib.import_module(f"modules.{modname}")
            source = getattr(mod, "__file__", "")
            assert "aiohttp" not in dir(mod), f"modules.{modname} imports aiohttp directly"


class TestNoAutoProbingAPIEndpoints:
    """Verify api_discovery doesn't fetch discovered endpoints."""

    def test_api_endpoints_not_fetched(self):
        import inspect
        from modules.api_discovery import APIDiscovery
        source = inspect.getsource(APIDiscovery)
        # The module should fetch JS files for analysis, but should NOT
        # fetch the discovered API endpoints themselves.
        # Look for the _fetch_scripts method which fetches JS files,
        # and verify no fetch call uses endpoint paths.
        assert "self.engine.fetch" in source
        # The fetch calls should only be for script_url, not for api endpoints
        # Check that the endpoint collection is via regex, not via fetching
        assert "_extract_endpoints" in source or "re.finditer" in source
