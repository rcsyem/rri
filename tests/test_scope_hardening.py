import json
import tempfile
import unittest

from pathlib import Path
from core.scope import ScopeEngine


class TestScopeURLHardening(unittest.TestCase):

    def setUp(self):
        self.scope = ScopeEngine("https://rafiqmajali.dpdns.org/")

    def check(self, url):
        return self.scope.check(url)[0]

    def test_normal_url_allowed(self):
        self.assertTrue(
            self.check("https://rafiqmajali.dpdns.org/")
        )

    def test_leading_space_rejected(self):
        self.assertFalse(
            self.check(" https://rafiqmajali.dpdns.org/")
        )

    def test_trailing_space_rejected(self):
        self.assertFalse(
            self.check("https://rafiqmajali.dpdns.org/ ")
        )

    def test_newline_rejected(self):
        self.assertFalse(
            self.check("https://rafiqmajali.dpdns.org\n/")
        )

    def test_tab_rejected(self):
        self.assertFalse(
            self.check("https://rafiqmajali.dpdns.org\t/")
        )

    def test_carriage_return_rejected(self):
        self.assertFalse(
            self.check("https://rafiqmajali.dpdns.org\r/")
        )

    def test_credentials_rejected(self):
        self.assertFalse(
            self.check(
                "https://user:pass@rafiqmajali.dpdns.org/"
            )
        )

    def test_empty_credentials_rejected(self):
        self.assertFalse(
            self.check("https://@rafiqmajali.dpdns.org/")
        )

    def test_wrong_https_port_rejected(self):
        self.assertFalse(
            self.check(
                "https://rafiqmajali.dpdns.org:8443/"
            )
        )

    def test_default_https_port_allowed(self):
        self.assertTrue(
            self.check(
                "https://rafiqmajali.dpdns.org:443/"
            )
        )

    def test_trailing_dot_allowed(self):
        self.assertTrue(
            self.check("https://rafiqmajali.dpdns.org./")
        )

    def test_external_suffix_rejected(self):
        self.assertFalse(
            self.check(
                "https://rafiqmajali.dpdns.org.evil.invalid/"
            )
        )

    def test_subdomain_rejected(self):
        self.assertFalse(
            self.check(
                "https://sub.rafiqmajali.dpdns.org/"
            )
        )

    def test_encoded_path_rejected(self):
        self.assertFalse(
            self.check(
                "https://rafiqmajali.dpdns.org/%2e%2e/admin"
            )
        )

    def test_double_slash_path_rejected(self):
        self.assertFalse(
            self.check(
                "https://rafiqmajali.dpdns.org//admin"
            )
        )

    def test_fragment_rejected(self):
        self.assertFalse(
            self.check(
                "https://rafiqmajali.dpdns.org/#fragment"
            )
        )

    def test_backslash_rejected(self):
        self.assertFalse(
            self.check(
                "https://rafiqmajali.dpdns.org/\\admin"
            )
        )

    def test_invalid_scheme_rejected(self):
        self.assertFalse(
            self.check(
                "ftp://rafiqmajali.dpdns.org/"
            )
        )

    def test_non_string_target_rejected(self):
        self.assertFalse(self.check(None))


class TestMultipleScopeAssets(unittest.TestCase):

    def create_scope(self, assets):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        path = Path(self.temp_dir.name) / "scope.json"

        path.write_text(
            json.dumps({"authorized_assets": assets}),
            encoding="utf-8"
        )

        return ScopeEngine(path)

    def test_same_domain_different_paths(self):
        scope = self.create_scope([
            {
                "domain": "example.invalid",
                "allowed_paths": ["/shop"]
            },
            {
                "domain": "example.invalid",
                "allowed_paths": ["/admin"]
            }
        ])

        self.assertTrue(
            scope.check("https://example.invalid/shop")[0]
        )

        self.assertTrue(
            scope.check("https://example.invalid/admin")[0]
        )

    def test_unauthorized_path_still_rejected(self):
        scope = self.create_scope([
            {
                "domain": "example.invalid",
                "allowed_paths": ["/shop"]
            },
            {
                "domain": "example.invalid",
                "allowed_paths": ["/admin"]
            }
        ])

        self.assertFalse(
            scope.check("https://example.invalid/private")[0]
        )

    def test_subdomains_remain_disabled_by_default(self):
        scope = self.create_scope([
            {
                "domain": "example.invalid",
                "allowed_paths": ["/"]
            }
        ])

        self.assertFalse(
            scope.check("https://api.example.invalid/")[0]
        )

    def test_explicit_subdomains_setting(self):
        scope = self.create_scope([
            {
                "domain": "example.invalid",
                "include_subdomains": True,
                "allowed_paths": ["/"]
            }
        ])

        self.assertTrue(
            scope.check("https://api.example.invalid/")[0]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestRuntimeTargetScope(unittest.TestCase):

    def test_runtime_target_authorizes_its_exact_host(self):
        scope = ScopeEngine("https://shop.example.invalid/catalog")
        self.assertTrue(scope.check("https://shop.example.invalid/")[0])
        self.assertTrue(
            scope.check("https://shop.example.invalid/private/item")[0]
        )

    def test_runtime_target_blocks_other_domain(self):
        scope = ScopeEngine("https://shop.example.invalid/")
        self.assertFalse(scope.check("https://other.example.invalid/")[0])

    def test_runtime_target_blocks_subdomains(self):
        scope = ScopeEngine("https://example.invalid/")
        self.assertFalse(scope.check("https://api.example.invalid/")[0])

    def test_suffix_attack_blocked(self):
        scope = ScopeEngine("https://example.invalid/")
        self.assertFalse(
            scope.check("https://example.invalid.evil.invalid/")[0]
        )

    def test_empty_scope_fails_closed(self):
        scope = ScopeEngine()
        self.assertFalse(scope.check("https://example.invalid/")[0])

    def test_invalid_runtime_target_rejected(self):
        targets = (
            "ftp://example.invalid/",
            "https://user:pass@example.invalid/",
            "https://example.invalid:8443/",
            "https://127.0.0.1/",
        )

        for target in targets:
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    ScopeEngine(target)
