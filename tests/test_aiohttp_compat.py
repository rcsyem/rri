"""Tests for HTTP Engine aiohttp compatibility.

Verifies that the HTTP Engine works across aiohttp versions that
support and don't support the max_headers parameter (added in 3.14).
The project allows aiohttp>=3.12,<4, so we must handle both cases.
"""

import inspect
import unittest
from unittest.mock import MagicMock, patch, AsyncMock

import aiohttp

from core.http_engine import HTTPEngine, _aiohttp_supports_max_headers
from core.scope import ScopeEngine


class TestAiohttpCompatibility(unittest.TestCase):

    def test_max_headers_detection(self):
        """The detection function returns a boolean."""
        result = _aiohttp_supports_max_headers()
        self.assertIsInstance(result, bool)

    def test_detection_matches_actual_aiohttp(self):
        """Detection should match the actual installed aiohttp version."""
        params = inspect.signature(
            aiohttp.ClientSession.__init__
        ).parameters
        expected = "max_headers" in params
        self.assertEqual(_aiohttp_supports_max_headers(), expected)

    def test_engine_constructs_regardless_of_aiohttp_version(self):
        """Engine should construct without error on any supported aiohttp."""
        scope = ScopeEngine("https://example.invalid/")
        engine = HTTPEngine(scope=scope)
        self.assertIsNotNone(engine)
        self.assertGreater(engine.max_header_count, 0)

    def test_header_count_limit_preserved(self):
        """The max_header_count value is always stored on the engine."""
        engine = HTTPEngine(max_header_count=200)
        self.assertEqual(engine.max_header_count, 200)

        engine2 = HTTPEngine(max_header_count=50)
        self.assertEqual(engine2.max_header_count, 50)


class TestHTTPHeaderCountEnforcement(unittest.TestCase):
    """Verify header count limits are enforced regardless of aiohttp version."""

    def setUp(self):
        self.scope = ScopeEngine("https://example.invalid/")

    def test_engine_has_header_count_limit(self):
        engine = HTTPEngine(scope=self.scope)
        self.assertEqual(engine.max_header_count, 128)

    def test_custom_header_count_limit(self):
        engine = HTTPEngine(scope=self.scope, max_header_count=64)
        self.assertEqual(engine.max_header_count, 64)

    def test_header_count_limit_rejects_zero(self):
        with self.assertRaises(ValueError):
            HTTPEngine(scope=self.scope, max_header_count=0)

    def test_header_count_limit_rejects_negative(self):
        with self.assertRaises(ValueError):
            HTTPEngine(scope=self.scope, max_header_count=-1)


if __name__ == "__main__":
    unittest.main()
