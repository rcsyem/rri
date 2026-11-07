import unittest

from modules.headers_analysis import HeadersAnalyzer


class FakeEngine:

    def __init__(self, response):
        self.response = response
        self.targets = []

    async def fetch(self, target):
        self.targets.append(target)
        return self.response


class TestHeadersAnalyzer(unittest.IsolatedAsyncioTestCase):

    TARGET = "https://example.invalid/"

    def make_response(self, headers=None, **kwargs):

        response = {
            "status": "completed",
            "url": self.TARGET,
            "http_status": 200,
            "headers": headers or {},
            "error": None
        }

        response.update(kwargs)
        return response

    async def analyze(self, headers=None, **kwargs):

        engine = FakeEngine(
            self.make_response(headers, **kwargs)
        )

        result = await HeadersAnalyzer(engine).scan(
            self.TARGET
        )

        return result, engine

    async def test_returns_completed_status(self):

        result, _ = await self.analyze()

        self.assertEqual(result["status"], "completed")

    async def test_missing_hsts_detected_on_https(self):

        result, _ = await self.analyze()

        ids = [item["id"] for item in result["findings"]]

        self.assertIn("HSTS_MISSING", ids)

    async def test_hsts_not_required_on_http(self):

        engine = FakeEngine(
            self.make_response(
                url="http://example.invalid/"
            )
        )

        result = await HeadersAnalyzer(engine).scan(
            "http://example.invalid/"
        )

        ids = [item["id"] for item in result["findings"]]

        self.assertNotIn("HSTS_MISSING", ids)

    async def test_valid_hsts(self):

        result, _ = await self.analyze({
            "Strict-Transport-Security":
                "max-age=31536000; includeSubDomains"
        })

        ids = [item["id"] for item in result["findings"]]

        self.assertNotIn("HSTS_MISSING", ids)
        self.assertNotIn("HSTS_INVALID", ids)

    async def test_hsts_zero_max_age(self):

        result, _ = await self.analyze({
            "Strict-Transport-Security": "max-age=0"
        })

        ids = [item["id"] for item in result["findings"]]

        self.assertIn("HSTS_DISABLED", ids)

    async def test_hsts_invalid_max_age(self):

        result, _ = await self.analyze({
            "Strict-Transport-Security": "includeSubDomains"
        })

        ids = [item["id"] for item in result["findings"]]

        self.assertIn("HSTS_INVALID", ids)

    async def test_missing_csp_detected(self):

        result, _ = await self.analyze()

        ids = [item["id"] for item in result["findings"]]

        self.assertIn("CSP_MISSING", ids)

    async def test_unsafe_inline_detected(self):

        result, _ = await self.analyze({
            "Content-Security-Policy":
                "default-src 'self'; script-src 'unsafe-inline'"
        })

        ids = [item["id"] for item in result["findings"]]

        self.assertIn("CSP_UNSAFE_INLINE", ids)

    async def test_unsafe_eval_detected(self):

        result, _ = await self.analyze({
            "Content-Security-Policy":
                "script-src 'self' 'unsafe-eval'"
        })

        ids = [item["id"] for item in result["findings"]]

        self.assertIn("CSP_UNSAFE_EVAL", ids)

    async def test_csp_wildcard_detected(self):

        result, _ = await self.analyze({
            "Content-Security-Policy":
                "default-src *"
        })

        ids = [item["id"] for item in result["findings"]]

        self.assertIn("CSP_WILDCARD_SOURCE", ids)

    async def test_frame_ancestors_prevents_xfo_missing_warning(self):

        result, _ = await self.analyze({
            "Content-Security-Policy":
                "default-src 'self'; frame-ancestors 'none'"
        })

        ids = [item["id"] for item in result["findings"]]

        self.assertNotIn("X_FRAME_OPTIONS_MISSING", ids)

    async def test_cookie_missing_flags(self):

        result, _ = await self.analyze({
            "Set-Cookie": "session=abc123; Path=/"
        })

        ids = [item["id"] for item in result["findings"]]

        self.assertIn("COOKIE_SECURE_MISSING", ids)
        self.assertIn("COOKIE_HTTPONLY_MISSING", ids)
        self.assertIn("COOKIE_SAMESITE_MISSING", ids)

    async def test_secure_cookie(self):

        result, _ = await self.analyze({
            "Set-Cookie":
                "session=abc123; Secure; HttpOnly; SameSite=Lax"
        })

        cookie_findings = [
            item for item in result["findings"]
            if item["category"] == "Cookie Security"
        ]

        self.assertEqual(cookie_findings, [])

    async def test_samesite_none_without_secure(self):

        result, _ = await self.analyze({
            "Set-Cookie":
                "session=abc123; HttpOnly; SameSite=None"
        })

        ids = [item["id"] for item in result["findings"]]

        self.assertIn(
            "COOKIE_SAMESITE_NONE_WITHOUT_SECURE",
            ids
        )

    async def test_server_disclosure(self):

        result, _ = await self.analyze({
            "Server": "nginx/1.26.0",
            "X-Powered-By": "PHP/8.3"
        })

        ids = [item["id"] for item in result["findings"]]

        self.assertIn("SERVER_DISCLOSURE", ids)
        self.assertIn("X_POWERED_BY_DISCLOSURE", ids)

    async def test_header_names_are_case_insensitive(self):

        result, _ = await self.analyze({
            "sTrIcT-tRaNsPoRt-SeCuRiTy": "max-age=31536000"
        })

        ids = [item["id"] for item in result["findings"]]

        self.assertNotIn("HSTS_MISSING", ids)

    async def test_multiple_set_cookie_headers(self):

        result, _ = await self.analyze([
            ("Set-Cookie", "first=1; Secure; HttpOnly; SameSite=Lax"),
            ("Set-Cookie", "second=2; Path=/")
        ])

        cookie_findings = [
            item for item in result["findings"]
            if item["category"] == "Cookie Security"
        ]

        self.assertTrue(
            any(item["evidence"] == "second"
                for item in cookie_findings)
        )

        self.assertFalse(
            any(item["evidence"] == "first"
                for item in cookie_findings)
        )

    async def test_severity_counts(self):

        result, _ = await self.analyze()

        total = sum(result["severity_counts"].values())

        self.assertEqual(total, result["finding_count"])

    async def test_failed_fetch_preserved(self):

        engine = FakeEngine({
            "status": "network_error",
            "error": "Connection failed"
        })

        result = await HeadersAnalyzer(engine).scan(
            self.TARGET
        )

        self.assertEqual(result["status"], "network_error")
        self.assertEqual(result["error"], "Connection failed")

    async def test_invalid_response(self):

        engine = FakeEngine(None)

        result = await HeadersAnalyzer(engine).scan(
            self.TARGET
        )

        self.assertEqual(result["status"], "error")

    async def test_engine_fetch_called_once(self):

        engine = FakeEngine(
            self.make_response()
        )

        await HeadersAnalyzer(engine).scan(self.TARGET)

        self.assertEqual(
            engine.targets,
            [self.TARGET]
        )

    async def test_shared_response_does_not_fetch_again(self):

        engine = FakeEngine(
            self.make_response()
        )

        response = self.make_response()

        await HeadersAnalyzer(engine).scan(
            self.TARGET,
            response=response
        )

        self.assertEqual(engine.targets, [])


if __name__ == "__main__":
    unittest.main()
