from urllib.parse import urljoin

from core.scope import ScopeEngine


class RedirectGuard:
    REDIRECT_CODES = {301, 302, 303, 307, 308}
    MAX_LOCATION_LENGTH = 8192

    def __init__(self, scope=None, max_redirects=5):
        if (
            isinstance(max_redirects, bool)
            or not isinstance(max_redirects, int)
            or max_redirects < 0
        ):
            raise ValueError(
                "max_redirects must be a non-negative integer"
            )

        self.scope = scope if scope is not None else ScopeEngine()
        self.max_redirects = max_redirects

    @staticmethod
    def _validate_location(location):
        if not isinstance(location, str) or not location:
            return False, "Missing or invalid redirect Location"

        if len(location) > RedirectGuard.MAX_LOCATION_LENGTH:
            return False, "Redirect Location is too long"

        # Do not silently normalize attacker-controlled Location values.
        if any(
            char.isspace()
            or ord(char) < 32
            or ord(char) == 127
            for char in location
        ):
            return False, "Whitespace or control character in Location"

        if "\\" in location:
            return False, "Backslashes in redirect Location are not allowed"

        return True, "Location syntax accepted"

    def validate(self, current_url, location, redirect_count):
        if (
            isinstance(redirect_count, bool)
            or not isinstance(redirect_count, int)
            or redirect_count < 0
        ):
            return False, None, "Invalid redirect count"

        if redirect_count >= self.max_redirects:
            return False, None, "Redirect limit exceeded"

        if not isinstance(current_url, str) or not current_url:
            return False, None, "Invalid current URL"

        # The redirect must originate from an authorized URL.
        try:
            current_allowed, current_reason = self.scope.check(
                current_url
            )
        except (ValueError, TypeError, AttributeError):
            return False, None, "Invalid current URL"

        if not current_allowed:
            return (
                False,
                None,
                f"Current URL is outside authorized scope: {current_reason}"
            )

        location_valid, location_reason = self._validate_location(
            location
        )

        if not location_valid:
            return False, None, location_reason

        try:
            next_url = urljoin(current_url, location)
        except (ValueError, TypeError):
            return False, None, "Malformed redirect URL"

        try:
            allowed, reason = self.scope.check(next_url)
        except (ValueError, TypeError, AttributeError):
            return False, None, "Malformed redirect URL"

        if not allowed:
            return False, None, f"Redirect blocked: {reason}"

        return True, next_url, "Redirect authorized"
