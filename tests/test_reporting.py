import json
import tempfile
import unittest
from pathlib import Path

from core.reporting import ReportGenerator


class ReportingTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.generator = ReportGenerator(
            report_dir=self.directory / "reports"
        )

        self.results = {
            "status": "completed",
            "technology": {
                "technologies": [
                    {
                        "name": "Example",
                        "category": "Framework",
                        "confidence": "high",
                        "score": 90,
                    }
                ]
            },
            "api_discovery": {
                "endpoints": [
                    {
                        "url": "https://example.invalid/api",
                        "category": "REST",
                        "confidence": "medium",
                        "score": 50,
                    }
                ]
            },
            "headers_analysis": {
                "findings": [
                    {
                        "severity": "medium",
                        "title": "Missing Header",
                        "category": "Headers",
                        "evidence": "Example evidence",
                        "recommendation": "Configure the header",
                    }
                ]
            },
            "security_checks": {"findings": []},
            "correlation": {"correlations": []},
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_json_generation(self):
        paths = self.generator.generate(
            self.results, "https://example.invalid", "json"
        )
        self.assertEqual(len(paths), 1)

        document = json.loads(paths[0].read_text(encoding="utf-8"))
        self.assertEqual(document["tool"], "RRI")
        self.assertEqual(document["results"]["status"], "completed")

    def test_html_generation(self):
        paths = self.generator.generate(
            self.results, "https://example.invalid", "html"
        )
        content = paths[0].read_text(encoding="utf-8")

        self.assertIn("RRI", content)
        self.assertIn("Technology Fingerprinting", content)
        self.assertIn("API Discovery", content)
        self.assertIn("Missing Header", content)

    def test_both_formats(self):
        paths = self.generator.generate(
            self.results, "https://example.invalid", "both"
        )
        self.assertEqual(len(paths), 2)
        self.assertEqual({path.suffix for path in paths}, {".html", ".json"})

    def test_html_escaping(self):
        malicious = {
            "status": "completed",
            "technology": {
                "technologies": [
                    {
                        "name": '<script>alert("x")</script>',
                        "category": "test",
                    }
                ]
            },
        }

        paths = self.generator.generate(
            malicious, "https://example.invalid", "html"
        )
        content = paths[0].read_text(encoding="utf-8")

        self.assertNotIn('<script>alert("x")</script>', content)
        self.assertIn("&lt;script&gt;", content)

    def test_custom_output(self):
        output = self.directory / "custom-report.json"
        paths = self.generator.generate(
            self.results,
            "https://example.invalid",
            "json",
            output=output,
        )
        self.assertEqual(paths[0], output)
        self.assertTrue(output.is_file())

    def test_invalid_format(self):
        with self.assertRaises(ValueError):
            self.generator.generate(
                self.results, "https://example.invalid", "xml"
            )

    def test_invalid_results(self):
        with self.assertRaises(ValueError):
            self.generator.generate(
                [], "https://example.invalid", "json"
            )

    def test_invalid_target(self):
        with self.assertRaises(ValueError):
            self.generator.generate(self.results, "", "json")


if __name__ == "__main__":
    unittest.main()
