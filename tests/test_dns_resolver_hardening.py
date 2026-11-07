import math
import socket
import unittest

from core.dns_resolver import SafeDNSResolver


class TestDNSConstructor(unittest.TestCase):

    def test_reject_invalid_timeouts(self):
        for value in (
            0,
            -1,
            True,
            float("nan"),
            float("inf"),
            float("-inf")
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    SafeDNSResolver(dns_timeout=value)

    def test_reject_non_callable_lookup(self):
        with self.assertRaises(ValueError):
            SafeDNSResolver(lookup="invalid")


class TestDNSResolver(unittest.IsolatedAsyncioTestCase):

    async def make_resolver(self, result):
        async def lookup(host, port, family):
            return result

        return SafeDNSResolver(lookup=lookup)

    async def test_accept_public_ipv4(self):
        result = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                0,
                ("8.8.8.8", 443)
            )
        ]

        resolver = await self.make_resolver(result)

        records = await resolver.resolve(
            "rri-test.invalid",
            443
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["host"], "8.8.8.8")

    async def test_accept_empty_flags(self):
        result = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("8.8.8.8", 443)
            )
        ]

        resolver = await self.make_resolver(result)
        records = await resolver.resolve("rri-test.invalid", 443)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["host"], "8.8.8.8")
        self.assertEqual(records[0]["flags"], 0)

    async def test_reject_nonempty_string_flags(self):
        result = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "invalid",
                ("8.8.8.8", 443)
            )
        ]

        resolver = await self.make_resolver(result)

        with self.assertRaises(OSError):
            await resolver.resolve("rri-test.invalid", 443)

    async def test_accept_public_ipv6(self):
        result = [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                0,
                ("2606:4700:4700::1111", 443, 0, 0)
            )
        ]

        resolver = await self.make_resolver(result)

        records = await resolver.resolve(
            "rri-test.invalid",
            443
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(
            records[0]["host"],
            "2606:4700:4700::1111"
        )

    async def test_reject_boolean_family(self):
        resolver = await self.make_resolver([])

        with self.assertRaises(OSError):
            await resolver.resolve(
                "rri-test.invalid",
                443,
                True
            )

    async def test_reject_invalid_protocol(self):
        result = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                9999,
                0,
                ("8.8.8.8", 443)
            )
        ]

        resolver = await self.make_resolver(result)

        with self.assertRaises(OSError):
            await resolver.resolve("rri-test.invalid", 443)

    async def test_reject_boolean_protocol(self):
        result = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                True,
                0,
                ("8.8.8.8", 443)
            )
        ]

        resolver = await self.make_resolver(result)

        with self.assertRaises(OSError):
            await resolver.resolve("rri-test.invalid", 443)

    async def test_reject_negative_flags(self):
        result = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                -1,
                ("8.8.8.8", 443)
            )
        ]

        resolver = await self.make_resolver(result)

        with self.assertRaises(OSError):
            await resolver.resolve("rri-test.invalid", 443)

    async def test_reject_private_address(self):
        result = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                0,
                ("127.0.0.1", 443)
            )
        ]

        resolver = await self.make_resolver(result)

        with self.assertRaises(OSError):
            await resolver.resolve("rri-test.invalid", 443)

    async def test_reject_hostname_with_whitespace(self):
        resolver = await self.make_resolver([])

        with self.assertRaises(OSError):
            await resolver.resolve(
                "rri test.invalid",
                443
            )

    async def test_reject_hostname_with_control_character(self):
        resolver = await self.make_resolver([])

        with self.assertRaises(OSError):
            await resolver.resolve(
                "rri-test.invalid\n",
                443
            )


if __name__ == "__main__":
    unittest.main()
