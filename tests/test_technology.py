import unittest
from core.scope import ScopeEngine

from modules.technology import (
    TechnologyDetector,
    PageAnalyzer
)


class FakeEngine:

    def __init__(self, response):
        self.response = response
        self.targets = []
        self.scope = ScopeEngine("https://example.invalid/")

    async def fetch(self, target):
        self.targets.append(target)
        return self.response


class TestPageAnalyzer(unittest.TestCase):

    def test_extracts_meta_and_assets(self):

        parser = PageAnalyzer()

        parser.feed("""
            <html>
                <head>
                    <meta name="generator" content="WordPress">
                    <script src="/assets/jquery.min.js"></script>
                    <link rel="stylesheet" href="/style.css">
                </head>
                <body>
                    <div id="app" class="container active"></div>
                </body>
            </html>
        """)

        self.assertEqual(
            parser.meta["generator"],
            "WordPress"
        )

        self.assertIn(
            "/assets/jquery.min.js",
            parser.scripts
        )

        self.assertIn(
            "/style.css",
            parser.stylesheets
        )

        self.assertIn("app", parser.ids)
        self.assertIn("container", parser.classes)


class TestTechnologyDetector(unittest.IsolatedAsyncioTestCase):

    def make_engine(self, headers=None, body=b""):

        return FakeEngine({
            "status": "completed",
            "url": "https://example.invalid/",
            "http_status": 200,
            "headers": headers or {},
            "body": body,
            "error": None
        })

    async def test_detects_nginx(self):

        engine = self.make_engine({
            "Server": "nginx/1.26.0"
        })

        result = await TechnologyDetector(engine).scan(
            "https://example.invalid/"
        )

        self.assertEqual(result["status"], "completed")

        names = [
            item["name"]
            for item in result["technologies"]
        ]

        self.assertIn("Nginx", names)

    async def test_detects_cloudflare(self):

        engine = self.make_engine({
            "CF-Ray": "123456-example",
            "Server": "cloudflare"
        })

        result = await TechnologyDetector(engine).scan(
            "https://example.invalid/"
        )

        names = [
            item["name"]
            for item in result["technologies"]
        ]

        self.assertIn("Cloudflare", names)

    async def test_detects_php_from_cookie(self):

        engine = self.make_engine({
            "Set-Cookie": "PHPSESSID=abc123; Path=/"
        })

        result = await TechnologyDetector(engine).scan(
            "https://example.invalid/"
        )

        names = [
            item["name"]
            for item in result["technologies"]
        ]

        self.assertIn("PHP", names)

    async def test_detects_laravel(self):

        engine = self.make_engine({
            "Set-Cookie": "laravel_session=abc123; Path=/"
        })

        result = await TechnologyDetector(engine).scan(
            "https://example.invalid/"
        )

        names = [
            item["name"]
            for item in result["technologies"]
        ]

        self.assertIn("Laravel", names)

    async def test_detects_wordpress(self):

        body = b"""
            <html>
                <head>
                    <meta name="generator" content="WordPress 6">
                </head>
                <body>
                    <script src="/wp-content/themes/demo/app.js"></script>
                </body>
            </html>
        """

        engine = self.make_engine(body=body)

        result = await TechnologyDetector(engine).scan(
            "https://example.invalid/"
        )

        names = [
            item["name"]
            for item in result["technologies"]
        ]

        self.assertIn("WordPress", names)

    async def test_detects_nextjs(self):

        body = b"""
            <html>
                <script id="__NEXT_DATA__" type="application/json">
                    {}
                </script>
                <script src="/_next/static/chunks/main.js"></script>
            </html>
        """

        engine = self.make_engine(body=body)

        result = await TechnologyDetector(engine).scan(
            "https://example.invalid/"
        )

        names = [
            item["name"]
            for item in result["technologies"]
        ]

        self.assertIn("Next.js", names)

    async def test_detects_jquery_asset(self):

        body = b"""
            <html>
                <script src="/js/jquery.min.js"></script>
            </html>
        """

        engine = self.make_engine(body=body)

        result = await TechnologyDetector(engine).scan(
            "https://example.invalid/"
        )

        names = [
            item["name"]
            for item in result["technologies"]
        ]

        self.assertIn("jQuery", names)

    async def test_detects_react_inline(self):

        body = b"""
            <html>
                <script>
                    ReactDOM.createRoot(document.getElementById("root"));
                </script>
            </html>
        """

        engine = self.make_engine(body=body)

        result = await TechnologyDetector(engine).scan(
            "https://example.invalid/"
        )

        names = [
            item["name"]
            for item in result["technologies"]
        ]

        self.assertIn("React", names)

    async def test_evidence_is_preserved(self):

        engine = self.make_engine({
            "Server": "nginx"
        })

        result = await TechnologyDetector(engine).scan(
            "https://example.invalid/"
        )

        nginx = next(
            item
            for item in result["technologies"]
            if item["name"] == "Nginx"
        )

        self.assertGreater(nginx["score"], 0)
        self.assertEqual(nginx["confidence"], "high")
        self.assertTrue(nginx["evidence"])

        evidence = nginx["evidence"][0]

        self.assertEqual(evidence["source"], "header")
        self.assertEqual(evidence["indicator"], "Server")

    async def test_technologies_are_sorted_by_score(self):

        engine = self.make_engine({
            "Server": "nginx",
            "CF-Ray": "123456"
        })

        result = await TechnologyDetector(engine).scan(
            "https://example.invalid/"
        )

        scores = [
            item["score"]
            for item in result["technologies"]
        ]

        self.assertEqual(scores, sorted(scores, reverse=True))

    async def test_empty_page_returns_no_findings(self):

        engine = self.make_engine()

        result = await TechnologyDetector(engine).scan(
            "https://example.invalid/"
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["technology_count"], 0)
        self.assertEqual(result["technologies"], [])

    async def test_network_error_is_preserved(self):

        engine = FakeEngine({
            "status": "network_error",
            "url": "https://example.invalid/",
            "error": "Connection failed"
        })

        result = await TechnologyDetector(engine).scan(
            "https://example.invalid/"
        )

        self.assertEqual(result["status"], "network_error")
        self.assertEqual(result["technologies"], [])
        self.assertEqual(result["error"], "Connection failed")

    async def test_engine_receives_original_target(self):

        engine = self.make_engine()

        target = "https://example.invalid/"

        await TechnologyDetector(engine).scan(target)

        self.assertEqual(engine.targets, [target])

    async def test_detects_multiple_technologies(self):

        body = b"""
            <html>
                <head>
                    <meta name="generator" content="WordPress">
                </head>
                <body>
                    <script src="/js/jquery.min.js"></script>
                    <script src="/_next/static/chunks/main.js"></script>
                </body>
            </html>
        """

        engine = self.make_engine({
            "Server": "nginx",
            "CF-Ray": "123456"
        }, body)

        result = await TechnologyDetector(engine).scan(
            "https://example.invalid/"
        )

        names = {
            item["name"]
            for item in result["technologies"]
        }

        self.assertTrue({
            "Nginx",
            "Cloudflare",
            "WordPress",
            "jQuery",
            "Next.js"
        }.issubset(names))


if __name__ == "__main__":
    unittest.main()
