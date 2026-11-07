import unittest

from urllib.parse import urlsplit

from modules.api_discovery import (
    APIDiscovery,
    APIPageParser
)


HOST = "rri-test.invalid"


class FakeScope:

    def check(self, url):

        try:
            parsed = urlsplit(url)

            if parsed.scheme not in ("http", "https"):
                return False, "Invalid scheme"

            if parsed.hostname != HOST:
                return False, "Outside scope"

            if parsed.username or parsed.password:
                return False, "Credentials forbidden"

            return True, "Authorized"

        except ValueError:
            return False, "Malformed URL"


class FakeEngine:

    def __init__(self, responses=None):
        self.scope = FakeScope()
        self.responses = responses or {}
        self.requests = []

    async def fetch(self, target):

        self.requests.append(target)

        return self.responses.get(
            target,
            {
                "status": "network_error",
                "url": target,
                "error": "Not found"
            }
        )


class TestAPIPageParser(unittest.TestCase):

    def test_extracts_scripts_and_links(self):

        parser = APIPageParser()

        parser.feed("""
            <html>
                <script src="/assets/app.js"></script>
                <a href="/api/docs">API Docs</a>
                <script>
                    const endpoint = "/api/v1/users";
                </script>
            </html>
        """)

        self.assertIn(
            "/assets/app.js",
            parser.scripts
        )

        self.assertIn(
            "/api/docs",
            parser.links
        )

        self.assertTrue(
            any(
                "/api/v1/users" in item
                for item in parser.inline_scripts
            )
        )


class TestAPIDiscovery(unittest.IsolatedAsyncioTestCase):

    def make_response(self, body):

        return {
            "status": "completed",
            "url": f"https://{HOST}/",
            "http_status": 200,
            "headers": {
                "Content-Type": "text/html"
            },
            "body": body,
            "error": None
        }

    async def test_discovers_rest_endpoint(self):

        engine = FakeEngine()

        response = self.make_response(
            b'<script>fetch("/api/v1/users")</script>'
        )

        result = await APIDiscovery(engine).scan(
            f"https://{HOST}/",
            response
        )

        urls = [
            item["url"]
            for item in result["endpoints"]
        ]

        self.assertIn(
            f"https://{HOST}/api/v1/users",
            urls
        )

    async def test_discovers_graphql(self):

        engine = FakeEngine()

        response = self.make_response(
            b'<script>const client = new ApolloClient({});</script>'
        )

        result = await APIDiscovery(engine).scan(
            f"https://{HOST}/",
            response
        )

        self.assertTrue(
            any(
                item["category"] == "GraphQL Candidate"
                for item in result["endpoints"]
            )
        )

    async def test_discovers_graphql_path(self):

        engine = FakeEngine()

        response = self.make_response(
            b'<script>fetch("/graphql")</script>'
        )

        result = await APIDiscovery(engine).scan(
            f"https://{HOST}/",
            response
        )

        self.assertTrue(
            any(
                item["category"] == "GraphQL"
                for item in result["endpoints"]
            )
        )

    async def test_discovers_openapi_reference(self):

        engine = FakeEngine()

        response = self.make_response(
            b'<script>const docs = "/openapi.json";</script>'
        )

        result = await APIDiscovery(engine).scan(
            f"https://{HOST}/",
            response
        )

        self.assertTrue(
            any(
                item["category"] == "API Documentation"
                for item in result["endpoints"]
            )
        )

    async def test_discovers_swagger_reference(self):

        engine = FakeEngine()

        response = self.make_response(
            b'<script>const docs = "/swagger.json";</script>'
        )

        result = await APIDiscovery(engine).scan(
            f"https://{HOST}/",
            response
        )

        self.assertTrue(
            any(
                "swagger.json" in item["url"]
                for item in result["endpoints"]
            )
        )

    async def test_fetches_authorized_javascript(self):

        script_url = f"https://{HOST}/assets/app.js"

        engine = FakeEngine({
            script_url: {
                "status": "completed",
                "url": script_url,
                "body": b'fetch("/api/v2/orders")',
                "headers": {},
                "http_status": 200
            }
        })

        response = self.make_response(
            b'<script src="/assets/app.js"></script>'
        )

        result = await APIDiscovery(engine).scan(
            f"https://{HOST}/",
            response
        )

        self.assertIn(script_url, engine.requests)

        self.assertTrue(
            any(
                "/api/v2/orders" in item["url"]
                for item in result["endpoints"]
            )
        )

    async def test_external_script_is_not_fetched(self):

        engine = FakeEngine()

        response = self.make_response(
            b'<script src="https://evil.invalid/app.js"></script>'
        )

        result = await APIDiscovery(engine).scan(
            f"https://{HOST}/",
            response
        )

        self.assertEqual(engine.requests, [])
        self.assertEqual(
            result["script_files_fetched"],
            0
        )

    async def test_relative_script_is_resolved(self):

        script_url = f"https://{HOST}/assets/app.js"

        engine = FakeEngine({
            script_url: {
                "status": "completed",
                "url": script_url,
                "body": b'fetch("/api/users")',
                "headers": {},
                "http_status": 200
            }
        })

        response = self.make_response(
            b'<script src="/assets/app.js"></script>'
        )

        await APIDiscovery(engine).scan(
            f"https://{HOST}/",
            response
        )

        self.assertEqual(
            engine.requests,
            [script_url]
        )

    async def test_duplicate_endpoints_are_merged(self):

        engine = FakeEngine()

        response = self.make_response(
            b"""
            <script>
                fetch("/api/users");
                fetch("/api/users");
            </script>
            """
        )

        result = await APIDiscovery(engine).scan(
            f"https://{HOST}/",
            response
        )

        matching = [
            item
            for item in result["endpoints"]
            if item["url"].endswith("/api/users")
        ]

        self.assertEqual(len(matching), 1)

    async def test_scope_rejects_unauthorized_page(self):

        engine = FakeEngine()

        response = {
            "status": "completed",
            "url": "https://evil.invalid/",
            "body": b'fetch("/api/users")'
        }

        result = await APIDiscovery(engine).scan(
            f"https://{HOST}/",
            response
        )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["endpoints"], [])

    async def test_detects_api_from_inline_script(self):

        engine = FakeEngine()

        response = self.make_response(
            b"""
            <script>
                const endpoint = "/api/v1/products";
            </script>
            """
        )

        result = await APIDiscovery(engine).scan(
            f"https://{HOST}/",
            response
        )

        self.assertGreater(result["endpoint_count"], 0)

    async def test_evidence_is_preserved(self):

        engine = FakeEngine()

        response = self.make_response(
            b'<script>fetch("/api/users")</script>'
        )

        result = await APIDiscovery(engine).scan(
            f"https://{HOST}/",
            response
        )

        endpoint = result["endpoints"][0]

        self.assertTrue(endpoint["evidence"])
        self.assertTrue(endpoint["sources"])
        self.assertIsNotNone(endpoint["confidence"])

    async def test_script_limit_is_respected(self):

        engine = FakeEngine()

        response = self.make_response(
            b"""
            <script src="/a.js"></script>
            <script src="/b.js"></script>
            <script src="/c.js"></script>
            """
        )

        result = await APIDiscovery(
            engine,
            max_script_files=2
        ).scan(
            f"https://{HOST}/",
            response
        )

        self.assertEqual(
            result["script_files_discovered"],
            2
        )

        self.assertLessEqual(
            len(engine.requests),
            2
        )

    async def test_invalid_script_limit_is_rejected(self):

        with self.assertRaises(ValueError):
            APIDiscovery(
                FakeEngine(),
                max_script_files=-1
            )

    async def test_failed_page_fetch_is_preserved(self):

        engine = FakeEngine()

        result = await APIDiscovery(engine).scan(
            f"https://{HOST}/"
        )

        self.assertEqual(
            result["status"],
            "network_error"
        )

        self.assertEqual(
            result["endpoint_count"],
            0
        )


if __name__ == "__main__":
    unittest.main()
