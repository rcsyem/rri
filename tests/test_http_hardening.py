import math
import unittest

from core.http_engine import HTTPEngine
from core.redirect_guard import RedirectGuard


class AllowScope:

    def check(self, url):
        if not isinstance(url, str):
            return False, "Invalid URL"

        if url.startswith("https://rri-test.invalid/"):
            return True, "Authorized"

        return False, "Outside test scope"


class TestHTTPValidation(unittest.TestCase):

    def test_reject_invalid_timeouts(self):
        for value in (0, -1, True, float("nan"), float("inf")):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    HTTPEngine(timeout=value)

    def test_reject_invalid_response_sizes(self):
        for value in (0, -1, True, 1.5, "100"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    HTTPEngine(max_response_size=value)

    def test_reject_invalid_header_limits(self):
        for name in (
            "max_header_count",
            "max_header_field_size",
            "max_header_line_size"
        ):
            for value in (0, -1, True, 1.5):
                with self.subTest(name=name, value=value):
                    with self.assertRaises(ValueError):
                        HTTPEngine(**{name: value})


class TestRedirectGuardHardening(unittest.TestCase):

    def setUp(self):
        self.guard = RedirectGuard(AllowScope(), max_redirects=2)

    def test_relative_redirect(self):
        valid, url, _ = self.guard.validate(
            "https://rri-test.invalid/",
            "/next",
            0
        )
        self.assertTrue(valid)
        self.assertEqual(url, "https://rri-test.invalid/next")

    def test_external_redirect_blocked(self):
        valid, _, _ = self.guard.validate(
            "https://rri-test.invalid/",
            "https://example.com/",
            0
        )
        self.assertFalse(valid)

    def test_missing_location_blocked(self):
        valid, _, _ = self.guard.validate(
            "https://rri-test.invalid/",
            None,
            0
        )
        self.assertFalse(valid)

    def test_non_string_location_blocked(self):
        valid, _, _ = self.guard.validate(
            "https://rri-test.invalid/",
            123,
            0
        )
        self.assertFalse(valid)

    def test_long_location_blocked(self):
        valid, _, _ = self.guard.validate(
            "https://rri-test.invalid/",
            "/" + ("a" * 9000),
            0
        )
        self.assertFalse(valid)

    def test_invalid_redirect_count(self):
        for count in (-1, True, 1.5):
            valid, _, _ = self.guard.validate(
                "https://rri-test.invalid/",
                "/next",
                count
            )
            self.assertFalse(valid)

    def test_zero_redirect_limit(self):
        guard = RedirectGuard(AllowScope(), max_redirects=0)
        valid, _, _ = guard.validate(
            "https://rri-test.invalid/",
            "/next",
            0
        )
        self.assertFalse(valid)

    def test_invalid_max_redirects(self):
        for value in (-1, True, 1.5):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    RedirectGuard(AllowScope(), value)


if __name__ == "__main__":
    unittest.main()


class TestRedirectLocationHeaders(unittest.TestCase):

    def setUp(self):
        from multidict import CIMultiDict
        self.CIMultiDict = CIMultiDict

    def test_single_location_is_accepted(self):
        headers = self.CIMultiDict()
        headers.add("Location", "/next")

        valid, location, error = (
            HTTPEngine._extract_redirect_location(headers)
        )

        self.assertTrue(valid)
        self.assertEqual(location, "/next")
        self.assertIsNone(error)

    def test_missing_location_is_returned_for_guard_validation(self):
        headers = self.CIMultiDict()

        valid, location, error = (
            HTTPEngine._extract_redirect_location(headers)
        )

        self.assertTrue(valid)
        self.assertIsNone(location)
        self.assertIsNone(error)

    def test_duplicate_location_is_rejected(self):
        headers = self.CIMultiDict()
        headers.add("Location", "/first")
        headers.add("Location", "/second")

        valid, location, error = (
            HTTPEngine._extract_redirect_location(headers)
        )

        self.assertFalse(valid)
        self.assertIsNone(location)
        self.assertIn("Multiple", error)
