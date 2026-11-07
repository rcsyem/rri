import unittest

from core.correlation_engine import CorrelationEngine


class TestCorrelationOrigin(unittest.TestCase):

    def test_same_https_origin(self):
        target = CorrelationEngine._origin(
            "https://example.invalid/"
        )

        self.assertTrue(
            CorrelationEngine._same_origin(
                "https://example.invalid/api",
                target
            )
        )

    def test_default_https_port_matches_explicit_port(self):
        target = CorrelationEngine._origin(
            "https://example.invalid/"
        )

        self.assertTrue(
            CorrelationEngine._same_origin(
                "https://example.invalid:443/api",
                target
            )
        )

    def test_default_http_port_matches_explicit_port(self):
        target = CorrelationEngine._origin(
            "http://example.invalid/"
        )

        self.assertTrue(
            CorrelationEngine._same_origin(
                "http://example.invalid:80/api",
                target
            )
        )

    def test_different_scheme_rejected(self):
        target = CorrelationEngine._origin(
            "https://example.invalid/"
        )

        self.assertFalse(
            CorrelationEngine._same_origin(
                "http://example.invalid/api",
                target
            )
        )

    def test_different_port_rejected(self):
        target = CorrelationEngine._origin(
            "https://example.invalid/"
        )

        self.assertFalse(
            CorrelationEngine._same_origin(
                "https://example.invalid:8443/api",
                target
            )
        )

    def test_different_host_rejected(self):
        target = CorrelationEngine._origin(
            "https://example.invalid/"
        )

        self.assertFalse(
            CorrelationEngine._same_origin(
                "https://outside.invalid/api",
                target
            )
        )

    def test_subdomain_rejected(self):
        target = CorrelationEngine._origin(
            "https://example.invalid/"
        )

        self.assertFalse(
            CorrelationEngine._same_origin(
                "https://api.example.invalid/api",
                target
            )
        )

    def test_credentials_rejected(self):
        target = CorrelationEngine._origin(
            "https://example.invalid/"
        )

        self.assertFalse(
            CorrelationEngine._same_origin(
                "https://user:pass@example.invalid/api",
                target
            )
        )

    def test_invalid_port_rejected(self):
        self.assertIsNone(
            CorrelationEngine._origin(
                "https://example.invalid:99999/api"
            )
        )

    def test_malformed_url_rejected(self):
        self.assertIsNone(
            CorrelationEngine._origin(
                "https://[invalid/api"
            )
        )

    def test_non_http_scheme_rejected(self):
        self.assertIsNone(
            CorrelationEngine._origin(
                "ftp://example.invalid/file"
            )
        )

    def test_trailing_dot_normalized(self):
        target = CorrelationEngine._origin(
            "https://example.invalid./"
        )

        self.assertTrue(
            CorrelationEngine._same_origin(
                "https://example.invalid/api",
                target
            )
        )

    def test_invalid_target_does_not_crash_analysis(self):
        result = CorrelationEngine().analyze(
            "not a valid URL",
            api_discovery={
                "status": "completed",
                "endpoints": [
                    {
                        "url": "https://example.invalid/api/users"
                    }
                ]
            },
            security_checks={
                "status": "completed",
                "findings": [
                    {
                        "id": "TEST-1",
                        "severity": "low",
                        "evidence": "/api/users"
                    }
                ]
            }
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["summary"]["correlation_count"], 0)


if __name__ == "__main__":
    unittest.main()
