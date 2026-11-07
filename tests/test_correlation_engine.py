import unittest

from core.correlation_engine import CorrelationEngine


class TestCorrelationEngine(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationEngine()
        self.target = "https://example.invalid/"

    def test_empty_results(self):
        result = self.engine.analyze(self.target)

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["summary"]["correlation_count"], 0)

    def test_result_counts(self):
        result = self.engine.analyze(
            self.target,
            technology={
                "status": "completed",
                "technologies": [{"name": "Nginx"}]
            },
            api_discovery={
                "status": "completed",
                "endpoints": [{"url": "https://example.invalid/api"}]
            }
        )

        self.assertEqual(result["summary"]["technology_count"], 1)
        self.assertEqual(result["summary"]["endpoint_count"], 1)

    def test_security_path_overlap(self):
        result = self.engine.analyze(
            self.target,
            api_discovery={
                "status": "completed",
                "endpoints": [{
                    "url": "https://example.invalid/api/users",
                    "confidence": "high"
                }]
            },
            security_checks={
                "status": "completed",
                "findings": [{
                    "id": "TEST-001",
                    "severity": "medium",
                    "confidence": "high",
                    "evidence": "/api/users"
                }]
            }
        )

        self.assertEqual(result["summary"]["correlation_count"], 1)
        self.assertEqual(
            result["correlations"][0]["type"],
            "endpoint_security_overlap"
        )

    def test_header_path_overlap(self):
        result = self.engine.analyze(
            self.target,
            api_discovery={
                "status": "completed",
                "endpoints": [{
                    "url": "https://example.invalid/api/data",
                    "confidence": "medium"
                }]
            },
            headers_analysis={
                "status": "completed",
                "findings": [{
                    "id": "HEADER-001",
                    "severity": "low",
                    "confidence": "medium",
                    "evidence": "Affected path: /api/data"
                }]
            }
        )

        self.assertEqual(result["summary"]["correlation_count"], 1)
        self.assertEqual(
            result["correlations"][0]["type"],
            "endpoint_header_overlap"
        )

    def test_technology_path_overlap(self):
        result = self.engine.analyze(
            self.target,
            technology={
                "status": "completed",
                "technologies": [{
                    "name": "Example",
                    "confidence": "high",
                    "evidence": [{
                        "value": "/api/items"
                    }]
                }]
            },
            api_discovery={
                "status": "completed",
                "endpoints": [{
                    "url": "https://example.invalid/api/items",
                    "confidence": "high"
                }]
            }
        )

        self.assertEqual(result["summary"]["correlation_count"], 1)
        self.assertEqual(
            result["correlations"][0]["type"],
            "endpoint_technology_evidence"
        )

    def test_unrelated_paths_do_not_correlate(self):
        result = self.engine.analyze(
            self.target,
            api_discovery={
                "status": "completed",
                "endpoints": [{
                    "url": "https://example.invalid/api/users"
                }]
            },
            security_checks={
                "status": "completed",
                "findings": [{
                    "severity": "high",
                    "evidence": "/admin"
                }]
            }
        )

        self.assertEqual(result["summary"]["correlation_count"], 0)

    def test_partial_path_does_not_match(self):
        result = self.engine.analyze(
            self.target,
            api_discovery={
                "status": "completed",
                "endpoints": [{
                    "url": "https://example.invalid/api"
                }]
            },
            security_checks={
                "status": "completed",
                "findings": [{
                    "severity": "high",
                    "evidence": "/apiary"
                }]
            }
        )

        self.assertEqual(result["summary"]["correlation_count"], 0)

    def test_external_endpoint_ignored(self):
        result = self.engine.analyze(
            self.target,
            api_discovery={
                "status": "completed",
                "endpoints": [{
                    "url": "https://outside.invalid/api/users"
                }]
            },
            security_checks={
                "status": "completed",
                "findings": [{
                    "severity": "high",
                    "evidence": "/api/users"
                }]
            }
        )

        self.assertEqual(result["summary"]["correlation_count"], 0)

    def test_invalid_module_result_ignored(self):
        result = self.engine.analyze(
            self.target,
            technology="invalid",
            api_discovery=None,
            headers_analysis=[],
            security_checks={}
        )

        self.assertEqual(result["summary"]["technology_count"], 0)
        self.assertEqual(result["summary"]["endpoint_count"], 0)

    def test_failed_module_result_ignored(self):
        result = self.engine.analyze(
            self.target,
            security_checks={
                "status": "error",
                "findings": [{
                    "severity": "critical",
                    "evidence": "/api/users"
                }]
            }
        )

        self.assertEqual(result["summary"]["security_finding_count"], 0)

    def test_confidence_is_conservative(self):
        result = self.engine.analyze(
            self.target,
            api_discovery={
                "status": "completed",
                "endpoints": [{
                    "url": "https://example.invalid/api/users",
                    "confidence": "high"
                }]
            },
            security_checks={
                "status": "completed",
                "findings": [{
                    "severity": "medium",
                    "confidence": "low",
                    "evidence": "/api/users"
                }]
            }
        )

        self.assertEqual(result["correlations"][0]["confidence"], "low")

    def test_severity_counts(self):
        result = self.engine.analyze(
            self.target,
            api_discovery={
                "status": "completed",
                "endpoints": [{
                    "url": "https://example.invalid/api/users"
                }]
            },
            security_checks={
                "status": "completed",
                "findings": [{
                    "id": "A",
                    "severity": "high",
                    "evidence": "/api/users"
                }]
            }
        )

        counts = result["summary"]["severity_counts"]

        self.assertEqual(counts["high"], 1)
        self.assertEqual(counts["critical"], 0)

    def test_non_string_evidence_does_not_crash(self):
        result = self.engine.analyze(
            self.target,
            api_discovery={
                "status": "completed",
                "endpoints": [{
                    "url": "https://example.invalid/api/users"
                }]
            },
            security_checks={
                "status": "completed",
                "findings": [{
                    "severity": "low",
                    "evidence": None
                }]
            }
        )

        self.assertEqual(result["summary"]["correlation_count"], 0)

    def test_output_is_passive(self):
        result = self.engine.analyze(self.target)

        self.assertEqual(result["analysis_mode"], "passive")

    def test_correlation_has_caveat(self):
        result = self.engine.analyze(
            self.target,
            api_discovery={
                "status": "completed",
                "endpoints": [{
                    "url": "https://example.invalid/api/users"
                }]
            },
            security_checks={
                "status": "completed",
                "findings": [{
                    "severity": "low",
                    "evidence": "/api/users"
                }]
            }
        )

        self.assertIn("caveat", result["correlations"][0])

    def test_invalid_endpoint_url_ignored(self):
        result = self.engine.analyze(
            self.target,
            api_discovery={
                "status": "completed",
                "endpoints": [{
                    "url": "not-a-valid-url"
                }]
            },
            security_checks={
                "status": "completed",
                "findings": [{
                    "severity": "high",
                    "evidence": "/api"
                }]
            }
        )

        self.assertEqual(result["summary"]["correlation_count"], 0)

    def test_duplicate_correlations_removed(self):
        finding = {
            "id": "A",
            "severity": "low",
            "evidence": "/api/users"
        }

        result = self.engine.analyze(
            self.target,
            api_discovery={
                "status": "completed",
                "endpoints": [
                    {"url": "https://example.invalid/api/users"},
                    {"url": "https://example.invalid/api/users"}
                ]
            },
            security_checks={
                "status": "completed",
                "findings": [finding]
            }
        )

        self.assertEqual(result["summary"]["correlation_count"], 1)


if __name__ == "__main__":
    unittest.main()
