import unittest

from core.redirect_guard import RedirectGuard


class TestScope:
    def check(self, url):
        if not isinstance(url, str):
            return False, "Invalid URL"

        if url.startswith("https://rri-test.invalid/"):
            return True, "Authorized"

        return False, "Outside test scope"


class TestRedirectGuardHardening(unittest.TestCase):

    def setUp(self):
        self.guard = RedirectGuard(TestScope(), max_redirects=3)
        self.current = "https://rri-test.invalid/"

    def validate(self, location, count=0, current=None):
        return self.guard.validate(
            current if current is not None else self.current,
            location,
            count
        )

    def test_relative_redirect(self):
        valid, url, _ = self.validate("/next")
        self.assertTrue(valid)
        self.assertEqual(url, "https://rri-test.invalid/next")

    def test_parent_relative_redirect(self):
        valid, url, _ = self.validate("../next")
        self.assertTrue(valid)
        self.assertEqual(url, "https://rri-test.invalid/next")

    def test_query_only_redirect(self):
        valid, url, _ = self.validate("?page=2")
        self.assertTrue(valid)
        self.assertEqual(url, "https://rri-test.invalid/?page=2")

    def test_external_redirect_blocked(self):
        valid, url, _ = self.validate("https://evil.invalid/")
        self.assertFalse(valid)
        self.assertIsNone(url)

    def test_protocol_relative_external_redirect_blocked(self):
        valid, url, _ = self.validate("//evil.invalid/path")
        self.assertFalse(valid)
        self.assertIsNone(url)

    def test_similar_domain_blocked(self):
        valid, _, _ = self.validate(
            "https://rri-test.invalid.evil.invalid/"
        )
        self.assertFalse(valid)

    def test_scheme_change_blocked(self):
        valid, _, _ = self.validate("http://rri-test.invalid/")
        self.assertFalse(valid)

    def test_credentials_blocked(self):
        valid, _, _ = self.validate(
            "https://user:pass@rri-test.invalid/"
        )
        self.assertFalse(valid)

    def test_javascript_scheme_blocked(self):
        valid, _, _ = self.validate("javascript:alert(1)")
        self.assertFalse(valid)

    def test_leading_whitespace_rejected(self):
        valid, _, _ = self.validate(" /next")
        self.assertFalse(valid)

    def test_trailing_whitespace_rejected(self):
        valid, _, _ = self.validate("/next ")
        self.assertFalse(valid)

    def test_newline_rejected(self):
        valid, _, _ = self.validate("/next\n")
        self.assertFalse(valid)

    def test_tab_rejected(self):
        valid, _, _ = self.validate("/next\t")
        self.assertFalse(valid)

    def test_carriage_return_rejected(self):
        valid, _, _ = self.validate("/next\r")
        self.assertFalse(valid)

    def test_null_byte_rejected(self):
        valid, _, _ = self.validate("/next\x00")
        self.assertFalse(valid)

    def test_backslash_rejected(self):
        valid, _, _ = self.validate("\\\\evil.invalid\\path")
        self.assertFalse(valid)

    def test_empty_location_rejected(self):
        valid, _, _ = self.validate("")
        self.assertFalse(valid)

    def test_none_location_rejected(self):
        valid, _, _ = self.validate(None)
        self.assertFalse(valid)

    def test_long_location_rejected(self):
        valid, _, _ = self.validate(
            "/" + ("a" * 9000)
        )
        self.assertFalse(valid)

    def test_invalid_current_url_rejected(self):
        valid, _, _ = self.validate(
            "/next",
            current="https://evil.invalid/"
        )
        self.assertFalse(valid)

    def test_invalid_current_url_type_rejected(self):
        valid, _, _ = self.guard.validate(
            None,
            "/next",
            0
        )
        self.assertFalse(valid)

    def test_redirect_count_limit(self):
        valid, _, _ = self.validate("/next", count=3)
        self.assertFalse(valid)

    def test_redirect_count_before_limit(self):
        valid, _, _ = self.validate("/next", count=2)
        self.assertTrue(valid)

    def test_negative_redirect_count_rejected(self):
        valid, _, _ = self.validate("/next", count=-1)
        self.assertFalse(valid)

    def test_boolean_redirect_count_rejected(self):
        valid, _, _ = self.validate("/next", count=True)
        self.assertFalse(valid)

    def test_float_redirect_count_rejected(self):
        valid, _, _ = self.validate("/next", count=1.5)
        self.assertFalse(valid)

    def test_zero_redirect_limit(self):
        guard = RedirectGuard(TestScope(), max_redirects=0)

        valid, _, _ = guard.validate(
            self.current,
            "/next",
            0
        )

        self.assertFalse(valid)

    def test_invalid_max_redirects(self):
        for value in (-1, True, 1.5, "3", None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    RedirectGuard(TestScope(), value)

    def test_multiple_relative_redirects(self):
        first, first_url, _ = self.validate("/step1", count=0)
        self.assertTrue(first)

        second, second_url, _ = self.guard.validate(
            first_url, "/step2", 1
        )
        self.assertTrue(second)

        third, third_url, _ = self.guard.validate(
            second_url, "/step3", 2
        )
        self.assertTrue(third)

        fourth, _, _ = self.guard.validate(
            third_url, "/step4", 3
        )
        self.assertFalse(fourth)


if __name__ == "__main__":
    unittest.main(verbosity=2)
