import socket
import unittest

import aiohttp.web

from urllib.parse import urlsplit

from core.http_engine import HTTPEngine


HOST = "rri-test.invalid"


class TestScope:

    def check(self, target):
        try:
            parsed = urlsplit(target)

            if (
                parsed.scheme != "http"
                or parsed.hostname != HOST
                or parsed.username
                or parsed.password
            ):
                return False, "Outside test scope"

            return True, "Authorized test target"

        except ValueError:
            return False, "Invalid test URL"


class LocalTestResolver:

    def __init__(self):
        self.resolved_addresses = []

    async def resolve(
        self,
        host,
        port=0,
        family=socket.AF_UNSPEC
    ):

        if host != HOST:
            raise OSError("Unexpected hostname in test")

        record = {
            "hostname": host,
            "host": "127.0.0.1",
            "port": port,
            "family": socket.AF_INET,
            "proto": socket.IPPROTO_TCP,
            "flags": 0
        }

        self.resolved_addresses.append(record)

        return [record]

    async def close(self):
        pass


class TestHTTPEngine(HTTPEngine):
    __test__ = False

    def _create_resolver(self):
        self.test_resolver = LocalTestResolver()
        return self.test_resolver


class TestHTTPIntegration(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):

        self.observed_peer_ip = None
        self.observed_host = None

        app = aiohttp.web.Application()

        async def home(request):
            return aiohttp.web.Response(text="RRI HTTP TEST OK")

        async def connection_info(request):

            peer = request.transport.get_extra_info("peername")

            if peer:
                self.observed_peer_ip = peer[0]

            self.observed_host = request.headers.get("Host")

            return aiohttp.web.Response(
                text="CONNECTION INFO RECORDED"
            )

        async def not_found(request):
            return aiohttp.web.Response(
                status=404,
                text="Not Found"
            )

        async def server_error(request):
            return aiohttp.web.Response(
                status=500,
                text="Internal Error"
            )

        async def external_redirect(request):
            raise aiohttp.web.HTTPFound(
                location="https://google.com/"
            )

        async def loop_redirect(request):
            raise aiohttp.web.HTTPFound(location="/loop")

        async def large_response(request):
            return aiohttp.web.Response(body=b"A" * 2048)

        app.router.add_get("/", home)
        app.router.add_get("/connection-info", connection_info)
        app.router.add_get("/404", not_found)
        app.router.add_get("/500", server_error)
        app.router.add_get("/external", external_redirect)
        app.router.add_get("/loop", loop_redirect)
        app.router.add_get("/large", large_response)

        self.runner = aiohttp.web.AppRunner(app)
        await self.runner.setup()

        self.site = aiohttp.web.TCPSite(
            self.runner,
            "127.0.0.1",
            0
        )

        await self.site.start()

        sockets = self.site._server.sockets
        self.port = sockets[0].getsockname()[1]

        self.base_url = f"http://{HOST}:{self.port}"

    async def asyncTearDown(self):
        await self.runner.cleanup()

    def create_engine(self, max_size=2 * 1024 * 1024):

        return TestHTTPEngine(
            scope=TestScope(),
            timeout=5,
            max_response_size=max_size,
            max_redirects=2
        )

    async def test_get_success(self):

        result = await self.create_engine().fetch(
            self.base_url + "/"
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["http_status"], 200)
        self.assertIn(b"RRI HTTP TEST OK", result["body"])

    async def test_connection_uses_validated_ip_and_preserves_host(self):

        engine = self.create_engine()

        result = await engine.fetch(
            self.base_url + "/connection-info"
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["http_status"], 200)

        # Verify the resolver returned the expected IP.
        self.assertTrue(engine.test_resolver.resolved_addresses)

        self.assertEqual(
            engine.test_resolver.resolved_addresses[0]["host"],
            "127.0.0.1"
        )

        # Verify the actual TCP peer address observed by the server.
        self.assertEqual(
            self.observed_peer_ip,
            "127.0.0.1"
        )

        # Verify the original hostname was preserved in HTTP Host.
        self.assertEqual(
            self.observed_host,
            f"{HOST}:{self.port}"
        )

    async def test_404_response(self):

        result = await self.create_engine().fetch(
            self.base_url + "/404"
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["http_status"], 404)

    async def test_500_response(self):

        result = await self.create_engine().fetch(
            self.base_url + "/500"
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["http_status"], 500)

    async def test_external_redirect_blocked(self):

        result = await self.create_engine().fetch(
            self.base_url + "/external"
        )

        self.assertEqual(result["status"], "redirect_blocked")

    async def test_redirect_loop_limited(self):

        result = await self.create_engine().fetch(
            self.base_url + "/loop"
        )

        self.assertEqual(result["status"], "redirect_blocked")

    async def test_response_size_limited(self):

        result = await self.create_engine(
            max_size=1024
        ).fetch(self.base_url + "/large")

        self.assertEqual(
            result["status"],
            "size_limit_exceeded"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
