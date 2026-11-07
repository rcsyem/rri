"""HTTP Information gathering module for RRI.

Collects structured HTTP response information including status code,
headers, content type, content length, server header, redirect count,
and final URL.  This is passive observation of the initial page fetch
response — no additional requests are made beyond the initial fetch.

Uses the unified data model (make_http_info) for structured output.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from core.models import make_http_info, make_module_result


class HTTPInfo:
    """Extracts structured HTTP response information."""

    def __init__(self, engine=None):
        self.engine = engine

    @staticmethod
    def _decode_headers(headers: Any) -> dict:
        if not isinstance(headers, dict):
            return {}
        return dict(headers)

    @staticmethod
    def _extract_server(headers: dict) -> str | None:
        for key, value in headers.items():
            if key.lower() == "server":
                return str(value) if value else None
        return None

    @staticmethod
    def _extract_content_type(headers: dict) -> str | None:
        for key, value in headers.items():
            if key.lower() in ("content-type", "content_type"):
                return str(value) if value else None
        return None

    @staticmethod
    def _extract_content_length(headers: dict) -> int | None:
        for key, value in headers.items():
            if key.lower() in ("content-length", "content_length"):
                try:
                    return int(value)
                except (ValueError, TypeError):
                    return None
        return None

    async def scan(
        self,
        target: str,
        response: dict | None = None,
    ) -> dict:
        """Extract HTTP information from the target response.

        Args:
            target: the seed URL
            response: pre-fetched response (if None, will fetch)
        """
        if not isinstance(target, str) or not target:
            return make_module_result(
                "http_info", status="error", target="",
                error="Target URL is required",
            )

        if response is None:
            if self.engine is None:
                return make_module_result(
                    "http_info", status="error", target=target,
                    error="No engine provided and no response supplied",
                )

            try:
                response = await self.engine.fetch(target)
            except Exception as e:
                return make_module_result(
                    "http_info", status="error", target=target,
                    error=str(e),
                )

        if not isinstance(response, dict):
            return make_module_result(
                "http_info", status="error", target=target,
                error="Invalid response",
            )

        if response.get("status") != "completed":
            return make_module_result(
                "http_info",
                status=response.get("status", "error"),
                target=target,
                error=response.get("error", "Fetch failed"),
            )

        page_url = response.get("url", target)
        headers = self._decode_headers(response.get("headers", {}))
        http_status = response.get("http_status")

        if self.engine is not None:
            allowed, reason = self.engine.scope.check(page_url)
            if not allowed:
                return make_module_result(
                    "http_info", status="blocked", target=target,
                    error=f"Page URL outside scope: {reason}",
                )

        server = self._extract_server(headers)
        content_type = self._extract_content_type(headers)
        content_length = self._extract_content_length(headers)

        body = response.get("body", b"")
        if isinstance(body, (bytes, bytearray)):
            actual_length = len(body)
        elif isinstance(body, str):
            actual_length = len(body.encode("utf-8"))
        else:
            actual_length = 0

        if content_length is None:
            content_length = actual_length

        redirect_url = response.get("redirect_url")
        redirect_count = 0
        if redirect_url and redirect_url != page_url:
            redirect_count = 1

        http_info = make_http_info(
            url=page_url,
            http_status=http_status,
            headers=headers,
            content_type=content_type,
            content_length=content_length,
            server=server,
            redirect_count=redirect_count,
            final_url=page_url,
        )

        return make_module_result(
            "http_info",
            target=page_url,
            http_info=http_info,
            server=server,
            content_type=content_type,
            content_length=content_length,
            http_status=http_status,
            header_count=len(headers),
            redirect_count=redirect_count,
        )
