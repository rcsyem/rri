import asyncio
import socket
import unittest

from core.scope import ScopeEngine
from core.network_safety import NetworkSafety
from core.dns_resolver import SafeDNSResolver
from core.redirect_guard import RedirectGuard
from core.http_engine import HTTPEngine


def make_dns_record(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET

    sockaddr = (
        (address, 443, 0, 0)
        if family == socket.AF_INET6
        else (address, 443)
    )

    return (
        family,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        0,
        sockaddr
    )


class TestScope(unittest.TestCase):

    def setUp(self):
        self.scope = ScopeEngine("https://rafiqmajali.dpdns.org/")

    def test_authorized_domain(self):

        allowed, _ = self.scope.check(
            "https://rafiqmajali.dpdns.org/"
        )

        self.assertTrue(allowed)

    def test_external_domain_blocked(self):

        allowed, _ = self.scope.check(
            "https://google.com/"
        )

        self.assertFalse(allowed)

    def test_subdomain_blocked(self):

        allowed, _ = self.scope.check(
            "https://sub.rafiqmajali.dpdns.org/"
        )

        self.assertFalse(allowed)


class TestNetworkSafety(unittest.TestCase):

    def test_public_ipv4(self):

        allowed, _ = NetworkSafety.validate_ip("8.8.8.8")

        self.assertTrue(allowed)

    def test_private_ipv4(self):

        allowed, _ = NetworkSafety.validate_ip("192.168.1.1")

        self.assertFalse(allowed)

    def test_loopback_ipv4(self):

        allowed, _ = NetworkSafety.validate_ip("127.0.0.1")

        self.assertFalse(allowed)

    def test_public_ipv6(self):

        allowed, _ = NetworkSafety.validate_ip(
            "2606:4700:4700::1111"
        )

        self.assertTrue(allowed)

    def test_loopback_ipv6(self):

        allowed, _ = NetworkSafety.validate_ip("::1")

        self.assertFalse(allowed)

    def test_private_ipv6(self):

        allowed, _ = NetworkSafety.validate_ip("fc00::1")

        self.assertFalse(allowed)

    def test_mapped_loopback_ipv6(self):

        allowed, _ = NetworkSafety.validate_ip(
            "::ffff:127.0.0.1"
        )

        self.assertFalse(allowed)

    def test_mapped_public_ipv6(self):

        allowed, _ = NetworkSafety.validate_ip(
            "::ffff:8.8.8.8"
        )

        self.assertTrue(allowed)

    def test_ipv6_zone_identifier_blocked(self):

        allowed, _ = NetworkSafety.validate_ip(
            "fe80::1%eth0"
        )

        self.assertFalse(allowed)

    def test_invalid_ip(self):

        allowed, _ = NetworkSafety.validate_ip(
            "not-an-ip"
        )

        self.assertFalse(allowed)

    def test_mixed_public_private_dns_blocked(self):

        allowed, _ = NetworkSafety.validate_dns_results([
            "8.8.8.8",
            "127.0.0.1"
        ])

        self.assertFalse(allowed)


class TestDNSResolver(unittest.IsolatedAsyncioTestCase):

    async def test_public_dns(self):

        async def fake_lookup(host, port, family):

            return [
                make_dns_record("8.8.8.8")
            ]

        resolver = SafeDNSResolver(
            lookup=fake_lookup
        )

        result = await resolver.resolve(
            "example.test",
            443
        )

        self.assertEqual(
            result[0]["host"],
            "8.8.8.8"
        )

    async def test_private_dns_blocked(self):

        async def fake_lookup(host, port, family):

            return [
                make_dns_record("127.0.0.1")
            ]

        resolver = SafeDNSResolver(
            lookup=fake_lookup
        )

        with self.assertRaises(OSError):
            await resolver.resolve("example.test", 443)

    async def test_mixed_dns_results_blocked(self):

        async def fake_lookup(host, port, family):

            return [
                make_dns_record("8.8.8.8"),
                make_dns_record("127.0.0.1")
            ]

        resolver = SafeDNSResolver(
            lookup=fake_lookup
        )

        with self.assertRaises(OSError):
            await resolver.resolve("example.test", 443)

    async def test_empty_dns_results_blocked(self):

        async def fake_lookup(host, port, family):
            return []

        resolver = SafeDNSResolver(
            lookup=fake_lookup
        )

        with self.assertRaises(OSError):
            await resolver.resolve("example.test", 443)

    async def test_invalid_dns_record_blocked(self):

        async def fake_lookup(host, port, family):

            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("not-an-ip", 443)
                )
            ]

        resolver = SafeDNSResolver(
            lookup=fake_lookup
        )

        with self.assertRaises(OSError):
            await resolver.resolve("example.test", 443)

    async def test_address_family_mismatch_blocked(self):

        async def fake_lookup(host, port, family):

            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("2606:4700:4700::1111", 443)
                )
            ]

        resolver = SafeDNSResolver(
            lookup=fake_lookup
        )

        with self.assertRaises(OSError):
            await resolver.resolve("example.test", 443)

    async def test_dns_timeout(self):

        async def fake_lookup(host, port, family):

            await asyncio.sleep(1)

            return [
                make_dns_record("8.8.8.8")
            ]

        resolver = SafeDNSResolver(
            dns_timeout=0.01,
            lookup=fake_lookup
        )

        with self.assertRaises(OSError):
            await resolver.resolve("example.test", 443)


class TestRedirectGuard(unittest.TestCase):

    def setUp(self):

        self.guard = RedirectGuard(
            ScopeEngine("https://rafiqmajali.dpdns.org/"),
            max_redirects=3
        )

    def test_relative_redirect(self):

        valid, url, _ = self.guard.validate(
            "https://rafiqmajali.dpdns.org/",
            "/admin",
            0
        )

        self.assertTrue(valid)

        self.assertEqual(
            url,
            "https://rafiqmajali.dpdns.org/admin"
        )

    def test_external_redirect_blocked(self):

        valid, _, _ = self.guard.validate(
            "https://rafiqmajali.dpdns.org/",
            "https://google.com/",
            0
        )

        self.assertFalse(valid)

    def test_redirect_limit(self):

        valid, _, _ = self.guard.validate(
            "https://rafiqmajali.dpdns.org/",
            "/admin",
            3
        )

        self.assertFalse(valid)


class TestHTTPEngine(unittest.IsolatedAsyncioTestCase):

    async def test_external_target_blocked(self):

        engine = HTTPEngine()

        result = await engine.fetch(
            "https://google.com/"
        )

        self.assertEqual(
            result["status"],
            "blocked"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestDNSResolverMalformedResults(unittest.IsolatedAsyncioTestCase):

    async def test_non_iterable_dns_results_blocked(self):

        async def fake_lookup(host, port, family):
            return 12345

        resolver = SafeDNSResolver(lookup=fake_lookup)

        with self.assertRaises(OSError):
            await resolver.resolve("example.test", 443)

    async def test_none_dns_results_blocked(self):

        async def fake_lookup(host, port, family):
            return None

        resolver = SafeDNSResolver(lookup=fake_lookup)

        with self.assertRaises(OSError):
            await resolver.resolve("example.test", 443)

    async def test_malformed_dns_record_blocked(self):

        async def fake_lookup(host, port, family):
            return [None]

        resolver = SafeDNSResolver(lookup=fake_lookup)

        with self.assertRaises(OSError):
            await resolver.resolve("example.test", 443)

    async def test_mapped_public_ipv6_dns(self):

        async def fake_lookup(host, port, family):
            return [
                make_dns_record("::ffff:8.8.8.8")
            ]

        resolver = SafeDNSResolver(lookup=fake_lookup)

        result = await resolver.resolve("example.test", 443)

        self.assertEqual(
            result[0]["host"],
            "::ffff:8.8.8.8"
        )

    async def test_mapped_private_ipv6_dns_blocked(self):

        async def fake_lookup(host, port, family):
            return [
                make_dns_record("::ffff:127.0.0.1")
            ]

        resolver = SafeDNSResolver(lookup=fake_lookup)

        with self.assertRaises(OSError):
            await resolver.resolve("example.test", 443)
