import unittest

from core.scope import ScopeEngine
from modules.security_checks import SecurityChecks


TARGET = "https://example.invalid/"


def make_response(body, url=TARGET):

    return {
        "status": "completed",
        "url": url,
        "http_status": 200,
        "headers": {},
        "body": body.encode("utf-8"),
        "error": None
    }


class FakeEngine:

    def __init__(self, response):
        self.response = response
        self.calls = 0
        self.scope = ScopeEngine("https://example.invalid/")

    async def fetch(self, target):
        self.calls += 1
        return self.response


class TestSecurityChecks(unittest.IsolatedAsyncioTestCase):

    def make_scanner(self, response=None):
        return SecurityChecks(FakeEngine(response or make_response("")))

    async def test_empty_page(self):

        result = await self.make_scanner().scan(
            TARGET,
            make_response("<html><body>Hello</body></html>")
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["finding_count"], 0)

    async def test_admin_reference(self):

        body = '<a href="/admin/">Admin</a>'

        result = await self.make_scanner().scan(
            TARGET,
            make_response(body)
        )

        ids = {item["id"] for item in result["findings"]}

        self.assertIn("ADMIN_INTERFACE_REFERENCE", ids)

    async def test_external_admin_reference_ignored(self):

        body = '<a href="https://other.invalid/admin/">Admin</a>'

        result = await self.make_scanner().scan(
            TARGET,
            make_response(body)
        )

        self.assertNotIn(
            "ADMIN_INTERFACE_REFERENCE",
            {item["id"] for item in result["findings"]}
        )

    async def test_sensitive_file_reference(self):

        body = '<a href="/backup/database.sql">Backup</a>'

        result = await self.make_scanner().scan(
            TARGET,
            make_response(body)
        )

        self.assertIn(
            "SENSITIVE_FILE_REFERENCE",
            {item["id"] for item in result["findings"]}
        )

    async def test_env_reference(self):

        body = '<a href="/.env">Configuration</a>'

        result = await self.make_scanner().scan(
            TARGET,
            make_response(body)
        )

        self.assertIn(
            "SENSITIVE_FILE_REFERENCE",
            {item["id"] for item in result["findings"]}
        )

    async def test_debug_indicator(self):

        result = await self.make_scanner().scan(
            TARGET,
            make_response("Laravel Ignition")
        )

        self.assertIn(
            "DEBUG_PAGE_INDICATOR",
            {item["id"] for item in result["findings"]}
        )

    async def test_traceback_indicator(self):

        body = "Traceback (most recent call last):"

        result = await self.make_scanner().scan(
            TARGET,
            make_response(body)
        )

        self.assertIn(
            "ERROR_DETAIL_DISCLOSURE",
            {item["id"] for item in result["findings"]}
        )

    async def test_sql_error_indicator(self):

        result = await self.make_scanner().scan(
            TARGET,
            make_response("SQLSTATE[42000]: Syntax error")
        )

        self.assertIn(
            "ERROR_DETAIL_DISCLOSURE",
            {item["id"] for item in result["findings"]}
        )

    async def test_source_map_reference(self):

        body = "/*# sourceMappingURL=/assets/app.js.map */"

        result = await self.make_scanner().scan(
            TARGET,
            make_response(body)
        )

        self.assertIn(
            "SOURCE_MAP_REFERENCE",
            {item["id"] for item in result["findings"]}
        )

    async def test_external_source_map_ignored(self):

        body = "/*# sourceMappingURL=https://other.invalid/app.js.map */"

        result = await self.make_scanner().scan(
            TARGET,
            make_response(body)
        )

        self.assertNotIn(
            "SOURCE_MAP_REFERENCE",
            {item["id"] for item in result["findings"]}
        )

    async def test_directory_listing(self):

        body = """
        <html>
        <head><title>Index of /files/</title></head>
        <body><h1>Index of /files/</h1></body>
        </html>
        """

        result = await self.make_scanner().scan(
            TARGET,
            make_response(body)
        )

        self.assertIn(
            "DIRECTORY_LISTING_INDICATOR",
            {item["id"] for item in result["findings"]}
        )

    async def test_configuration_value_indicator_does_not_disclose_value(self):

        secret = "VERY_SECRET_TEST_VALUE_123456"

        body = "DB_PASSWORD=" + secret

        result = await self.make_scanner().scan(
            TARGET,
            make_response(body)
        )

        self.assertIn(
            "CONFIGURATION_VALUE_INDICATOR",
            {item["id"] for item in result["findings"]}
        )

        serialized = str(result)

        self.assertNotIn(secret, serialized)

    async def test_internal_path_indicator(self):

        body = "Error in /var/www/application/index.php"

        result = await self.make_scanner().scan(
            TARGET,
            make_response(body)
        )

        self.assertIn(
            "INTERNAL_DETAIL_DISCLOSURE",
            {item["id"] for item in result["findings"]}
        )

    async def test_private_ip_indicator(self):

        result = await self.make_scanner().scan(
            TARGET,
            make_response("Internal address: 192.168.1.20")
        )

        self.assertIn(
            "INTERNAL_DETAIL_DISCLOSURE",
            {item["id"] for item in result["findings"]}
        )

    async def test_fetch_once_when_response_missing(self):

        engine = FakeEngine(make_response("Hello"))

        result = await SecurityChecks(engine).scan(TARGET)

        self.assertEqual(result["status"], "completed")
        self.assertEqual(engine.calls, 1)

    async def test_shared_response_does_not_fetch(self):

        engine = FakeEngine(make_response("Hello"))

        result = await SecurityChecks(engine).scan(
            TARGET,
            response=make_response("Hello")
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(engine.calls, 0)

    async def test_failed_response_preserved(self):

        response = {
            "status": "network_error",
            "url": TARGET,
            "error": "Connection failed"
        }

        result = await self.make_scanner().scan(
            TARGET,
            response=response
        )

        self.assertEqual(result["status"], "network_error")
        self.assertEqual(result["finding_count"], 0)

    async def test_non_dict_response_rejected(self):

        result = await self.make_scanner().scan(
            TARGET,
            response=[]
        )

        self.assertEqual(result["status"], "error")

    async def test_severity_counts(self):

        result = await self.make_scanner().scan(
            TARGET,
            make_response("Laravel Ignition")
        )

        self.assertEqual(
            sum(result["severity_counts"].values()),
            result["finding_count"]
        )

    async def test_analysis_is_passive(self):

        engine = FakeEngine(make_response(
            '<a href="/admin/">Admin</a>'
        ))

        result = await SecurityChecks(engine).scan(
            TARGET,
            response=engine.response
        )

        self.assertEqual(engine.calls, 0)
        self.assertEqual(result["analysis_mode"], "passive")


if __name__ == "__main__":
    unittest.main()
