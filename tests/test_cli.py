import unittest

from main import Terminal, build_summary, get_version


class CLITests(unittest.TestCase):

    def test_summary_counts(self):
        results = {
            "technology": {
                "technologies": [{}, {}]
            },
            "api_discovery": {
                "endpoints": [{}, {}, {}]
            },
            "headers_analysis": {
                "findings": [
                    {"severity": "medium"},
                    {"severity": "low"},
                ]
            },
            "security_checks": {
                "findings": [
                    {"severity": "high"},
                    {"severity": "info"},
                ]
            },
            "correlation": {
                "correlations": [
                    {"severity": "critical"}
                ]
            },
        }

        summary = build_summary(results)

        self.assertEqual(summary["technologies"], 2)
        self.assertEqual(summary["api_endpoints"], 3)
        self.assertEqual(summary["header_findings"], 2)
        self.assertEqual(summary["security_findings"], 2)
        self.assertEqual(summary["correlations"], 1)

        self.assertEqual(summary["severity"]["critical"], 1)
        self.assertEqual(summary["severity"]["high"], 1)
        self.assertEqual(summary["severity"]["medium"], 1)
        self.assertEqual(summary["severity"]["low"], 1)
        self.assertEqual(summary["severity"]["info"], 1)

    def test_empty_results(self):
        summary = build_summary({})

        self.assertEqual(summary["technologies"], 0)
        self.assertEqual(summary["api_endpoints"], 0)
        self.assertEqual(summary["correlations"], 0)

    def test_invalid_module_data(self):
        summary = build_summary({
            "technology": None,
            "api_discovery": {"endpoints": None},
            "headers_analysis": {"findings": "invalid"},
        })

        self.assertEqual(summary["technologies"], 0)
        self.assertEqual(summary["api_endpoints"], 0)
        self.assertEqual(summary["header_findings"], 0)

    def test_terminal_without_color(self):
        terminal = Terminal(enabled=False)

        message = terminal.color("RRI", "green")

        self.assertEqual(message, "RRI")
        self.assertNotIn("\033[", message)

    def test_terminal_with_color(self):
        terminal = Terminal(enabled=True)

        message = terminal.color("RRI", "green")

        self.assertIn("\033[32m", message)
        self.assertIn("RRI", message)
        self.assertIn("\033[0m", message)

    def test_version_exists(self):
        version = get_version()

        self.assertIsInstance(version, str)
        self.assertTrue(version)


if __name__ == "__main__":
    unittest.main()
