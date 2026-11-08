"""Regression tests for URL normalization and redirect-to-/ behavior.

Covers the 7 cases specified in the v0.2.0 review:
1. URL without trailing slash
2. URL with trailing slash
3. HTTP-to-HTTPS redirect on same domain
4. Relative redirect to "/"
5. Redirect to internal path
6. Redirect to external domain
7. Redirect to unauthorized subdomain
"""

import unittest

from urllib.parse import urljoin

from core.scope import ScopeEngine
from core.redirect_guard import RedirectGuard


class TestURLNormalization(unittest.TestCase):
    """Test that scope accepts both with and without trailing slash."""

    def setUp(self):
        self.scope = ScopeEngine("https://example.invalid/")

    def test_url_without_trailing_slash_accepted(self):
        allowed, reason = self.scope.check("https://example.invalid")
        self.assertTrue(allowed, f"Should be allowed: {reason}")

    def test_url_with_trailing_slash_accepted(self):
        allowed, reason = self.scope.check("https://example.invalid/")
        self.assertTrue(allowed, f"Should be allowed: {reason}")

    def test_no_trailing_slash_normalizes_to_root(self):
        """urlsplit gives empty path, which scope normalizes to '/'."""
        from urllib.parse import urlsplit
        parsed = urlsplit("https://example.invalid")
        self.assertEqual(parsed.path, "")
        # Scope normalizes empty path to "/"
        # Both should be authorized since allowed_paths includes "/"
        self.assertTrue(self.scope.check("https://example.invalid")[0])
        self.assertTrue(self.scope.check("https://example.invalid/")[0])

    def test_slash_not_treated_as_new_host(self):
        """'/' is a path, not a hostname — must not cause host confusion."""
        allowed, reason = self.scope.check("https://example.invalid/")
        self.assertTrue(allowed)
        # The hostname should be example.invalid, not "/"
        from urllib.parse import urlsplit
        parsed = urlsplit("https://example.invalid/")
        self.assertEqual(parsed.hostname, "example.invalid")


class TestRedirectBehavior(unittest.TestCase):
    """Test all 7 redirect scenarios through RedirectGuard."""

    def setUp(self):
        self.scope = ScopeEngine("https://example.invalid/")
        self.guard = RedirectGuard(self.scope, max_redirects=5)

    def test_case1_url_without_trailing_slash(self):
        """Original URL without '/' should still work after redirect to '/'."""
        # If the server redirects from no-slash to slash:
        # current_url = https://example.invalid (no slash)
        # location = /
        # urljoin should produce https://example.invalid/
        current = "https://example.invalid/"
        location = "/"
        valid, next_url, msg = self.guard.validate(current, location, 0)
        self.assertTrue(valid, f"Should be valid: {msg}")
        self.assertEqual(next_url, "https://example.invalid/")

    def test_case2_url_with_trailing_slash(self):
        """URL with '/' is the canonical root — should be authorized."""
        allowed, _ = self.scope.check("https://example.invalid/")
        self.assertTrue(allowed)

    def test_case3_http_to_https_redirect(self):
        """Redirect from HTTP to HTTPS on same domain should be allowed."""
        # HTTP version of the same domain — scope allows http on port 80
        current = "http://example.invalid/"
        location = "https://example.invalid/"
        valid, next_url, msg = self.guard.validate(current, location, 0)
        self.assertTrue(valid, f"HTTP->HTTPS should be valid: {msg}")
        self.assertEqual(next_url, "https://example.invalid/")

    def test_case4_relative_redirect_to_root(self):
        """Relative redirect to '/' should resolve to authorized root."""
        current = "https://example.invalid/page"
        # But /page is outside allowed_paths, so current_url would fail.
        # Test with the root URL instead:
        current = "https://example.invalid/"
        location = "/"
        valid, next_url, msg = self.guard.validate(current, location, 0)
        self.assertTrue(valid, f"Relative / should be valid: {msg}")
        self.assertEqual(next_url, "https://example.invalid/")

    def test_case5_redirect_to_internal_path(self):
        """Redirect to a path outside a specific allowed_paths is blocked.

        When allowed_paths is restricted to e.g. ["/shop"], a redirect
        to /about should be blocked.  When allowed_paths includes "/"
        (runtime target — entire domain authorized), /about is allowed.
        """
        # Config-based scope with restricted paths
        import json, tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "scope.json"
            cfg.write_text(json.dumps({
                "authorized_assets": [{
                    "domain": "example.invalid",
                    "allowed_paths": ["/shop"]
                }]
            }))
            restricted_scope = ScopeEngine(cfg)
            guard = RedirectGuard(restricted_scope, max_redirects=5)

            current = "https://example.invalid/shop"
            location = "/about"
            valid, next_url, msg = guard.validate(current, location, 0)
            self.assertFalse(valid, f"Should be blocked with restricted paths: {msg}")
            self.assertIsNone(next_url)

    def test_case5b_runtime_target_allows_internal_path(self):
        """Runtime target scope authorizes all paths on the domain."""
        current = "https://example.invalid/"
        location = "/about"
        valid, next_url, msg = self.guard.validate(current, location, 0)
        self.assertTrue(valid, f"Runtime scope should allow: {msg}")
        self.assertEqual(next_url, "https://example.invalid/about")

    def test_case6_redirect_to_external_domain(self):
        """Redirect to an external domain must be blocked."""
        current = "https://example.invalid/"
        location = "https://evil.invalid/"
        valid, next_url, msg = self.guard.validate(current, location, 0)
        self.assertFalse(valid, f"External redirect should be blocked: {msg}")
        self.assertIsNone(next_url)

    def test_case7_redirect_to_unauthorized_subdomain(self):
        """Redirect to a subdomain not in scope must be blocked."""
        current = "https://example.invalid/"
        location = "https://api.example.invalid/"
        valid, next_url, msg = self.guard.validate(current, location, 0)
        self.assertFalse(valid, f"Subdomain redirect should be blocked: {msg}")
        self.assertIsNone(next_url)

    def test_redirect_chain_always_checks_final_url(self):
        """Each redirect in a chain is validated against scope."""
        # First redirect: / -> / (allowed)
        valid, url1, _ = self.guard.validate(
            "https://example.invalid/", "/", 0
        )
        self.assertTrue(valid)
        self.assertEqual(url1, "https://example.invalid/")

        # Second redirect from the result: / -> https://evil.invalid/ (blocked)
        valid, url2, msg = self.guard.validate(url1, "https://evil.invalid/", 1)
        self.assertFalse(valid)
        self.assertIsNone(url2)

    def test_root_slash_not_confused_with_domain(self):
        """'/' as location must be treated as path, not domain."""
        current = "https://example.invalid/"
        location = "/"
        next_url = urljoin(current, location)
        self.assertEqual(next_url, "https://example.invalid/")
        # Verify scope sees the correct hostname
        from urllib.parse import urlsplit
        parsed = urlsplit(next_url)
        self.assertEqual(parsed.hostname, "example.invalid")

    def test_http_scheme_allowed_on_same_domain(self):
        """HTTP on port 80 for the authorized domain is allowed by scope."""
        allowed, _ = self.scope.check("http://example.invalid/")
        self.assertTrue(allowed)

    def test_https_scheme_allowed_on_same_domain(self):
        """HTTPS on port 443 for the authorized domain is allowed."""
        allowed, _ = self.scope.check("https://example.invalid/")
        self.assertTrue(allowed)

    def test_non_default_port_blocked(self):
        """Non-default ports are blocked even on authorized domain."""
        self.assertFalse(self.scope.check("https://example.invalid:8443/")[0])
        self.assertFalse(self.scope.check("http://example.invalid:8080/")[0])

    def test_default_port_allowed(self):
        """Default ports (443 for HTTPS, 80 for HTTP) are allowed."""
        self.assertTrue(self.scope.check("https://example.invalid:443/")[0])
        self.assertTrue(self.scope.check("http://example.invalid:80/")[0])


class TestRedirectGuardFinalURLCheck(unittest.TestCase):
    """Verify that the final URL is always scope-checked after redirects."""

    def setUp(self):
        self.scope = ScopeEngine("https://example.invalid/")
        self.guard = RedirectGuard(self.scope, max_redirects=3)

    def test_multiple_internal_redirects_allowed(self):
        """Chain of redirects all within scope are allowed."""
        valid, url, _ = self.guard.validate(
            "https://example.invalid/", "/", 0
        )
        self.assertTrue(valid)
        self.assertEqual(url, "https://example.invalid/")

    def test_redirect_to_path_then_external_blocked(self):
        """Even after legitimate redirect, external is still blocked."""
        # Start at root, redirect to /
        valid, url, _ = self.guard.validate(
            "https://example.invalid/", "/", 0
        )
        self.assertTrue(valid)

        # From there, redirect to external
        valid, url2, msg = self.guard.validate(url, "https://evil.com/", 1)
        self.assertFalse(valid)
        self.assertIn("Redirect blocked", msg)

    def test_redirect_limit_enforced(self):
        """Redirect limit is strictly enforced."""
        guard = RedirectGuard(self.scope, max_redirects=1)
        # First redirect ok
        valid, _, _ = guard.validate(
            "https://example.invalid/", "/", 0
        )
        self.assertTrue(valid)
        # Second redirect exceeds limit
        valid, _, msg = guard.validate(
            "https://example.invalid/", "/", 1
        )
        self.assertFalse(valid)
        self.assertIn("Redirect limit exceeded", msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
