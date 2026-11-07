import inspect
import math
import ssl

import aiohttp

from core.scope import ScopeEngine
from core.dns_resolver import SafeDNSResolver
from core.redirect_guard import RedirectGuard


def _aiohttp_supports_max_headers() -> bool:
    """Check whether the installed aiohttp version accepts max_headers.

    The parameter was added in aiohttp 3.14.  The project allows
    aiohttp>=3.12,<4, so we must conditionally pass it.
    """
    try:
        params = inspect.signature(
            aiohttp.ClientSession.__init__
        ).parameters
        return "max_headers" in params
    except (TypeError, ValueError):
        return False


class HTTPEngine:

    def __init__(
        self,
        scope=None,
        timeout=15,
        max_response_size=2 * 1024 * 1024,
        max_redirects=5,
        max_header_count=128,
        max_header_field_size=8190,
        max_header_line_size=8190
    ):

        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError(
                "Timeout must be a positive finite number"
            )

        if (
            isinstance(max_response_size, bool)
            or not isinstance(max_response_size, int)
            or max_response_size <= 0
        ):
            raise ValueError(
                "Maximum response size must be a positive integer"
            )

        for name, value in (
            ("max_header_count", max_header_count),
            ("max_header_field_size", max_header_field_size),
            ("max_header_line_size", max_header_line_size)
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
            ):
                raise ValueError(
                    f"{name} must be a positive integer"
                )

        self.scope = (
            scope if scope is not None else ScopeEngine()
        )

        self.timeout = float(timeout)
        self.max_response_size = max_response_size
        self.max_header_count = max_header_count
        self.max_header_field_size = max_header_field_size
        self.max_header_line_size = max_header_line_size

        self.redirect_guard = RedirectGuard(
            self.scope,
            max_redirects
        )

    def _create_resolver(self):
        return SafeDNSResolver()

    def _create_ssl_context(self):
        return ssl.create_default_context()

    @staticmethod
    def _extract_redirect_location(headers):
        try:
            locations = headers.getall("Location", [])
        except (AttributeError, TypeError):
            return (
                False,
                None,
                "Unable to validate redirect Location headers"
            )

        if len(locations) > 1:
            return (
                False,
                None,
                "Multiple redirect Location headers are not allowed"
            )

        if not locations:
            return True, None, None

        return True, locations[0], None

    async def fetch(self, target):

        if not isinstance(target, str):
            return {
                "status": "blocked",
                "url": target,
                "error": "Invalid target URL"
            }

        allowed, reason = self.scope.check(target)

        if not allowed:
            return {
                "status": "blocked",
                "url": target,
                "error": reason
            }

        current_url = target
        redirect_count = 0

        try:
            resolver = self._create_resolver()

            connector = aiohttp.TCPConnector(
                resolver=resolver,
                use_dns_cache=False,
                limit=5,
                ssl=self._create_ssl_context()
            )

            timeout = aiohttp.ClientTimeout(
                total=self.timeout,
                connect=min(5, self.timeout),
                sock_read=min(10, self.timeout)
            )

            session_kwargs = {
                "connector": connector,
                "timeout": timeout,
                "trust_env": False,
                "auto_decompress": False,
                "max_field_size": self.max_header_field_size,
                "max_line_size": self.max_header_line_size,
                "headers": {
                    "User-Agent": "RRI/0.1",
                    "Accept": "*/*",
                    "Accept-Encoding": "identity"
                }
            }

            if _aiohttp_supports_max_headers():
                session_kwargs["max_headers"] = self.max_header_count

            async with aiohttp.ClientSession(
                **session_kwargs
            ) as session:

                while True:

                    async with session.get(
                        current_url,
                        allow_redirects=False
                    ) as response:

                        if response.status in RedirectGuard.REDIRECT_CODES:

                            location_valid, location, location_error = (
                                self._extract_redirect_location(
                                    response.headers
                                )
                            )

                            if not location_valid:
                                return {
                                    "status": "redirect_blocked",
                                    "url": current_url,
                                    "http_status": response.status,
                                    "error": location_error
                                }

                            valid, next_url, message = (
                                self.redirect_guard.validate(
                                    current_url,
                                    location,
                                    redirect_count
                                )
                            )

                            if not valid:
                                return {
                                    "status": "redirect_blocked",
                                    "url": current_url,
                                    "http_status": response.status,
                                    "error": message
                                }

                            redirect_count += 1
                            current_url = next_url
                            continue

                        if (
                            not _aiohttp_supports_max_headers()
                            and len(response.headers) > self.max_header_count
                        ):
                            return {
                                "status": "blocked",
                                "url": current_url,
                                "http_status": response.status,
                                "error": "Response header count exceeds limit"
                            }

                        body = bytearray()

                        async for chunk in response.content.iter_chunked(
                            16384
                        ):

                            if (
                                len(body) + len(chunk)
                                > self.max_response_size
                            ):
                                return {
                                    "status": "size_limit_exceeded",
                                    "url": current_url,
                                    "http_status": response.status,
                                    "error": "Response size limit exceeded"
                                }

                            body.extend(chunk)

                        return {
                            "status": "completed",
                            "url": current_url,
                            "http_status": response.status,
                            "headers": dict(response.headers),
                            "header_items": list(
                                response.headers.items()
                            ),
                            "body": bytes(body),
                            "redirects": redirect_count,
                            "error": None
                        }

        except (
            aiohttp.ClientError,
            OSError,
            TimeoutError,
            ValueError
        ) as error:

            return {
                "status": "network_error",
                "url": current_url,
                "error": str(error)
            }
