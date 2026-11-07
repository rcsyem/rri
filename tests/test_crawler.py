"""Tests for modules/crawler.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.scope import ScopeEngine
from modules.crawler import Crawler, LinkExtractor


class TestLinkExtractor:
    def test_extracts_anchor_href(self):
        parser = LinkExtractor()
        parser.feed('<a href="/page1">Link</a>')
        parser.close()
        assert "/page1" in parser.links

    def test_extracts_script_src(self):
        parser = LinkExtractor()
        parser.feed('<script src="/app.js"></script>')
        parser.close()
        assert "/app.js" in parser.links

    def test_extracts_img_src(self):
        parser = LinkExtractor()
        parser.feed('<img src="/logo.png">')
        parser.close()
        assert "/logo.png" in parser.links

    def test_extracts_form_action(self):
        parser = LinkExtractor()
        parser.feed('<form action="/submit">')
        parser.close()
        assert "/submit" in parser.links

    def test_ignores_empty_href(self):
        parser = LinkExtractor()
        parser.feed('<a href="">Empty</a>')
        parser.close()
        assert "" not in parser.links

    def test_handles_multiple_links(self):
        parser = LinkExtractor()
        parser.feed('<a href="/a">A</a><a href="/b">B</a>')
        parser.close()
        assert len(parser.links) == 2


class TestCrawlerInit:
    def test_defaults(self):
        engine = MagicMock()
        c = Crawler(engine)
        assert c.max_depth == 3
        assert c.max_pages == 20

    def test_custom_limits(self):
        engine = MagicMock()
        c = Crawler(engine, max_depth=5, max_pages=50)
        assert c.max_depth == 5
        assert c.max_pages == 50

    def test_invalid_depth(self):
        engine = MagicMock()
        with pytest.raises(ValueError):
            Crawler(engine, max_depth=0)

    def test_invalid_pages(self):
        engine = MagicMock()
        with pytest.raises(ValueError):
            Crawler(engine, max_pages=0)


class TestCrawlerCrawl:
    def test_blocked_seed(self):
        scope = MagicMock()
        scope.check = MagicMock(return_value=(False, "Out of scope"))
        engine = MagicMock()
        engine.scope = scope

        c = Crawler(engine)
        result = asyncio.run(c.crawl("https://evil.com/"))

        assert result["status"] == "blocked"
        assert "outside scope" in result["error"]

    def test_empty_seed(self):
        engine = MagicMock()
        engine.scope = MagicMock()
        c = Crawler(engine)
        result = asyncio.run(c.crawl(""))
        assert result["status"] == "error"

    def test_single_page_no_links(self):
        scope = ScopeEngine("https://example.invalid/")

        def fetch_side_effect(url):
            return {
                "status": "completed",
                "url": url,
                "http_status": 200,
                "headers": {"Content-Type": "text/html"},
                "body": b"<html><body>No links here</body></html>",
            }

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(side_effect=fetch_side_effect)

        c = Crawler(engine, max_depth=2, max_pages=5)
        result = asyncio.run(c.crawl("https://example.invalid/"))

        assert result["status"] == "completed"
        assert result["pages_fetched"] == 1
        assert result["pages_failed"] == 0
        assert len(result["discovered_urls"]) >= 1

    def test_crawl_extracts_internal_links(self):
        scope = ScopeEngine("https://example.invalid/")
        page1 = b'<html><a href="/about">About</a><a href="/contact">Contact</a></html>'

        def fetch_side_effect(url):
            if url in ("https://example.invalid/", "https://example.invalid"):
                return {
                    "status": "completed",
                    "url": "https://example.invalid/",
                    "http_status": 200,
                    "headers": {},
                    "body": page1,
                }
            return {
                "status": "completed",
                "url": url,
                "http_status": 200,
                "headers": {},
                "body": b"<html><body>Page</body></html>",
            }

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(side_effect=fetch_side_effect)

        c = Crawler(engine, max_depth=2, max_pages=10)
        result = asyncio.run(c.crawl("https://example.invalid/"))

        urls = [u["url"] for u in result["discovered_urls"]]
        assert "https://example.invalid/" in urls
        assert "https://example.invalid/about" in urls
        assert "https://example.invalid/contact" in urls

    def test_crawl_rejects_external_links(self):
        scope = ScopeEngine("https://example.invalid/")
        page = b'<html><a href="https://other.com/page">External</a><a href="/internal">Internal</a></html>'

        def fetch_side_effect(url):
            return {
                "status": "completed", "url": url, "http_status": 200,
                "headers": {}, "body": page if url == "https://example.invalid/" else b"<html></html>",
            }

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(side_effect=fetch_side_effect)

        c = Crawler(engine, max_depth=1, max_pages=5)
        result = asyncio.run(c.crawl("https://example.invalid/"))

        urls = [u["url"] for u in result["discovered_urls"]]
        assert "https://other.com/page" not in urls
        assert "https://example.invalid/internal" in urls

    def test_crawl_rejects_subdomain(self):
        scope = ScopeEngine("https://example.invalid/")
        page = b'<html><a href="https://sub.example.invalid/page">Sub</a></html>'

        def fetch_side_effect(url):
            return {"status": "completed", "url": url, "http_status": 200, "headers": {}, "body": page}

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(side_effect=fetch_side_effect)

        c = Crawler(engine, max_depth=1, max_pages=5)
        result = asyncio.run(c.crawl("https://example.invalid/"))

        urls = [u["url"] for u in result["discovered_urls"]]
        assert "https://sub.example.invalid/page" not in urls

    def test_crawl_records_paths(self):
        scope = ScopeEngine("https://example.invalid/")
        page = b'<html><a href="/about">About</a></html>'

        def fetch_side_effect(url):
            return {"status": "completed", "url": url, "http_status": 200, "headers": {},
                    "body": page if url == "https://example.invalid/" else b"<html></html>"}

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(side_effect=fetch_side_effect)

        c = Crawler(engine, max_depth=1, max_pages=5)
        result = asyncio.run(c.crawl("https://example.invalid/"))

        paths = [p["path"] for p in result["discovered_paths"]]
        assert "/" in paths
        assert "/about" in paths

    def test_crawl_handles_fetch_failure(self):
        scope = ScopeEngine("https://example.invalid/")

        def fetch_side_effect(url):
            return {"status": "network_error", "url": url, "error": "Timeout"}

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(side_effect=fetch_side_effect)

        c = Crawler(engine, max_depth=1, max_pages=5)
        result = asyncio.run(c.crawl("https://example.invalid/"))

        assert result["pages_fetched"] == 0
        assert result["pages_failed"] == 1
        assert any(u["verification_status"] == "failed" for u in result["discovered_urls"])

    def test_crawl_skips_static_assets(self):
        scope = ScopeEngine("https://example.invalid/")
        page = b'<html><a href="/page">Page</a><img src="/logo.png"></html>'

        def fetch_side_effect(url):
            return {"status": "completed", "url": url, "http_status": 200, "headers": {},
                    "body": page if url == "https://example.invalid/" else b"<html></html>"}

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(side_effect=fetch_side_effect)

        c = Crawler(engine, max_depth=1, max_pages=10)
        result = asyncio.run(c.crawl("https://example.invalid/"))

        urls = [u["url"] for u in result["discovered_urls"]]
        assert "https://example.invalid/logo.png" in urls
        png_entry = [u for u in result["discovered_urls"] if "logo.png" in u["url"]][0]
        assert png_entry["verification_status"] == "discovered"

    def test_crawl_respects_max_pages(self):
        scope = ScopeEngine("https://example.invalid/")

        def fetch_side_effect(url):
            return {"status": "completed", "url": url, "http_status": 200, "headers": {}, "body": b"<html></html>"}

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(side_effect=fetch_side_effect)

        c = Crawler(engine, max_depth=1, max_pages=1)
        result = asyncio.run(c.crawl("https://example.invalid/"))

        assert result["pages_fetched"] <= 1

    def test_crawl_deduplicates_urls(self):
        scope = ScopeEngine("https://example.invalid/")
        page = b'<html><a href="/about">About</a><a href="/about">About again</a></html>'

        def fetch_side_effect(url):
            return {"status": "completed", "url": url, "http_status": 200, "headers": {},
                    "body": page if url == "https://example.invalid/" else b"<html></html>"}

        engine = MagicMock()
        engine.scope = scope
        engine.fetch = AsyncMock(side_effect=fetch_side_effect)

        c = Crawler(engine, max_depth=1, max_pages=5)
        result = asyncio.run(c.crawl("https://example.invalid/"))

        urls = [u["url"] for u in result["discovered_urls"]]
        assert urls.count("https://example.invalid/about") == 1
