"""Tests for modules/http_info.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.scope import ScopeEngine
from modules.http_info import HTTPInfo


class TestHTTPInfoInit:
    def test_defaults(self):
        hi = HTTPInfo()
        assert hi.engine is None

    def test_with_engine(self):
        engine = MagicMock()
        hi = HTTPInfo(engine=engine)
        assert hi.engine is engine


class TestHTTPInfoScan:
    def _make_response(self, url="https://example.invalid/", body=b"<html></html>", status=200, headers=None):
        return {
            "status": "completed",
            "url": url,
            "http_status": status,
            "headers": headers or {"Server": "nginx/1.25", "Content-Type": "text/html"},
            "body": body,
        }

    def test_empty_target(self):
        hi = HTTPInfo()
        result = asyncio.run(hi.scan(""))
        assert result["status"] == "error"

    def test_no_engine_no_response(self):
        hi = HTTPInfo()
        result = asyncio.run(hi.scan("https://example.invalid/"))
        assert result["status"] == "error"
        assert "engine" in result["error"].lower()

    def test_extracts_server(self):
        scope = ScopeEngine("https://example.invalid/")
        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response())

        hi = HTTPInfo(engine=engine)
        result = asyncio.run(hi.scan("https://example.invalid/"))

        assert result["server"] == "nginx/1.25"

    def test_extracts_content_type(self):
        scope = ScopeEngine("https://example.invalid/")
        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response())

        hi = HTTPInfo(engine=engine)
        result = asyncio.run(hi.scan("https://example.invalid/"))

        assert result["content_type"] == "text/html"

    def test_extracts_content_length_from_header(self):
        scope = ScopeEngine("https://example.invalid/")
        response = self._make_response(headers={"Content-Length": "1234", "Content-Type": "text/html"})
        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=response)

        hi = HTTPInfo(engine=engine)
        result = asyncio.run(hi.scan("https://example.invalid/"))

        assert result["content_length"] == 1234

    def test_content_length_from_body(self):
        scope = ScopeEngine("https://example.invalid/")
        response = self._make_response(body=b"x" * 500, headers={"Content-Type": "text/html"})
        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=response)

        hi = HTTPInfo(engine=engine)
        result = asyncio.run(hi.scan("https://example.invalid/"))

        assert result["content_length"] == 500

    def test_records_http_status(self):
        scope = ScopeEngine("https://example.invalid/")
        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response(status=301))

        hi = HTTPInfo(engine=engine)
        result = asyncio.run(hi.scan("https://example.invalid/"))

        assert result["http_status"] == 301

    def test_header_count(self):
        scope = ScopeEngine("https://example.invalid/")
        response = self._make_response(headers={"Server": "nginx", "Content-Type": "text/html", "X-Custom": "yes"})
        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=response)

        hi = HTTPInfo(engine=engine)
        result = asyncio.run(hi.scan("https://example.invalid/"))

        assert result["header_count"] == 3

    def test_blocked_by_scope(self):
        scope = MagicMock()
        scope.check = MagicMock(return_value=(False, "Out of scope"))
        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response("https://evil.com/"))

        hi = HTTPInfo(engine=engine)
        result = asyncio.run(hi.scan("https://evil.com/"))

        assert result["status"] == "blocked"

    def test_fetch_failure(self):
        scope = ScopeEngine("https://example.invalid/")
        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value={
            "status": "network_error", "url": "https://example.invalid/", "error": "Timeout",
        })

        hi = HTTPInfo(engine=engine)
        result = asyncio.run(hi.scan("https://example.invalid/"))

        assert result["status"] == "network_error"

    def test_http_info_dict_present(self):
        scope = ScopeEngine("https://example.invalid/")
        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(return_value=self._make_response())

        hi = HTTPInfo(engine=engine)
        result = asyncio.run(hi.scan("https://example.invalid/"))

        assert "http_info" in result
        assert isinstance(result["http_info"], dict)
        assert result["http_info"]["url"] == "https://example.invalid/"
        assert result["http_info"]["server"] == "nginx/1.25"

    def test_with_pre_supplied_response(self):
        hi = HTTPInfo()
        result = asyncio.run(hi.scan("https://example.invalid/", response=self._make_response()))
        assert result["status"] == "completed"
        assert result["server"] == "nginx/1.25"
