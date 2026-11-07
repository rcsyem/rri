import asyncio
import ipaddress
import socket
import ssl
import subprocess
import tempfile
import unittest

from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import web
from aiohttp.abc import AbstractResolver

from core.http_engine import HTTPEngine


HOST = "rri-test.invalid"


class TLSLocalResolver(AbstractResolver):

    async def resolve(self, host, port=0, family=socket.AF_UNSPEC):

        if host != HOST:
            raise OSError("Unexpected hostname")

        return [{
            "hostname": host,
            "host": "127.0.0.1",
            "port": port,
            "family": socket.AF_INET,
            "proto": socket.IPPROTO_TCP,
            "flags": 0
        }]

    async def close(self):
        pass


class TLSTestScope:

    def check(self, url):

        if not isinstance(url, str):
            return False, "Invalid URL"

        try:
            parsed = urlsplit(url)

            if parsed.scheme != "https":
                return False, "HTTPS required"

            if parsed.hostname != HOST:
                return False, "Unauthorized hostname"

            if parsed.username or parsed.password:
                return False, "Credentials are not allowed"

            if parsed.fragment:
                return False, "Fragments are not allowed"

            return True, "Authorized"

        except ValueError:
            return False, "Malformed URL"


class TrustedTLSEngine(HTTPEngine):

    def __init__(self, ca_file, **kwargs):
        self.ca_file = ca_file
        super().__init__(scope=TLSTestScope(), **kwargs)

    def _create_resolver(self):
        return TLSLocalResolver()

    def _create_ssl_context(self):
        return ssl.create_default_context(cafile=self.ca_file)


class UntrustedTLSEngine(HTTPEngine):

    def __init__(self, **kwargs):
        super().__init__(scope=TLSTestScope(), **kwargs)

    def _create_resolver(self):
        return TLSLocalResolver()


class TestTLSIntegration(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):

        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

        self.cert_file = self.temp_path / "cert.pem"
        self.key_file = self.temp_path / "key.pem"

        command = [
            "openssl", "req",
            "-x509",
            "-newkey", "rsa:2048",
            "-nodes",
            "-keyout", str(self.key_file),
            "-out", str(self.cert_file),
            "-days", "1",
            "-subj", f"/CN={HOST}",
            "-addext", f"subjectAltName=DNS:{HOST}",
            "-addext", "basicConstraints=critical,CA:TRUE"
        ]

        subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True
        )

        self.server_sni = []
        self.server_requests = []

        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        server_context.load_cert_chain(
            certfile=str(self.cert_file),
            keyfile=str(self.key_file)
        )

        def capture_sni(ssl_object, server_name, context):
            self.server_sni.append(server_name)

        server_context.set_servername_callback(capture_sni)

        async def handler(request):

            peer = request.transport.get_extra_info("peername")

            data = {
                "host": request.host,
                "peer_ip": peer[0] if peer else None
            }

            self.server_requests.append(data)

            return web.json_response(data)

        app = web.Application()
        app.router.add_get("/", handler)

        self.runner = web.AppRunner(app)
        await self.runner.setup()

        self.site = web.TCPSite(
            self.runner,
            "127.0.0.1",
            0,
            ssl_context=server_context
        )

        await self.site.start()

        sockets = self.site._server.sockets
        self.port = sockets[0].getsockname()[1]

        self.url = f"https://{HOST}:{self.port}/"

    async def asyncTearDown(self):

        if hasattr(self, "runner"):
            await self.runner.cleanup()

        if hasattr(self, "temp_dir"):
            self.temp_dir.cleanup()

    async def test_https_connection_preserves_sni_and_host(self):

        engine = TrustedTLSEngine(
            str(self.cert_file),
            timeout=10
        )

        result = await engine.fetch(self.url)

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["http_status"], 200)

        self.assertTrue(self.server_sni)
        self.assertEqual(self.server_sni[-1], HOST)

        self.assertTrue(self.server_requests)

        request = self.server_requests[-1]

        self.assertEqual(request["peer_ip"], "127.0.0.1")
        self.assertEqual(request["host"], f"{HOST}:{self.port}")

        self.assertEqual(
            result["url"],
            self.url
        )

    async def test_untrusted_certificate_is_rejected(self):

        engine = UntrustedTLSEngine(timeout=10)

        result = await engine.fetch(self.url)

        self.assertEqual(result["status"], "network_error")

        self.assertIn(
            "certificate",
            result["error"].lower()
        )


if __name__ == "__main__":
    unittest.main()
