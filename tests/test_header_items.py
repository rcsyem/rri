import unittest

from core.scope import ScopeEngine
from modules.headers_analysis import HeadersAnalyzer


class FakeEngine:
    def __init__(self, response):
        self.response = response
        self.calls = 0
        self.scope = ScopeEngine("https://example.invalid/")

    async def fetch(self, target):
        self.calls += 1
        return self.response


class TestRepeatedHeaders(unittest.IsolatedAsyncioTestCase):

    def test_normalize_preserves_repeated_values(self):
        items = [
            ("Set-Cookie", "session=abc; Path=/; HttpOnly"),
            ("Set-Cookie", "preferences=dark; Path=/"),
            ("X-Test", "one"),
            ("X-Test", "two"),
        ]

        result = HeadersAnalyzer._normalize_headers(items)

        self.assertEqual(
            result["set-cookie"],
            [
                "session=abc; Path=/; HttpOnly",
                "preferences=dark; Path=/",
            ],
        )

        self.assertEqual(
            result["x-test"],
            ["one", "two"],
        )

    async def test_scan_prefers_header_items(self):
        response = {
            "status": "completed",
            "url": "https://example.invalid/",
            "http_status": 200,

            # Simulates the old dictionary representation.
            "headers": {
                "Set-Cookie": "old=value; Path=/",
            },

            # Complete representation containing repeated fields.
            "header_items": [
                ("Set-Cookie", "session=abc; Path=/"),
                ("Set-Cookie", "preferences=dark; Path=/"),
            ],

            "body": b"",
            "error": None,
        }

        engine = FakeEngine(response)
        analyzer = HeadersAnalyzer(engine)

        result = await analyzer.scan("https://example.invalid/")

        self.assertEqual(result["status"], "completed")
        self.assertEqual(engine.calls, 1)

        cookie_findings = [
            finding
            for finding in result["findings"]
            if finding.get("category") == "Cookie Security"
        ]

        evidence = " ".join(
            str(finding.get("evidence", ""))
            for finding in cookie_findings
        )

        self.assertIn("session", evidence)
        self.assertIn("preferences", evidence)
        self.assertNotIn("old=value", evidence)

    async def test_scan_falls_back_to_legacy_headers(self):
        response = {
            "status": "completed",
            "url": "https://example.invalid/",
            "http_status": 200,
            "headers": {
                "Set-Cookie": "legacy=value; Path=/",
            },
            "body": b"",
            "error": None,
        }

        result = await HeadersAnalyzer(
            FakeEngine(response)
        ).scan("https://example.invalid/")

        self.assertEqual(result["status"], "completed")


if __name__ == "__main__":
    unittest.main()
