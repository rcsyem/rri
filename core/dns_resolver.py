import asyncio
import ipaddress
import math
import socket

from aiohttp.abc import AbstractResolver

from core.network_safety import NetworkSafety


class SafeDNSResolver(AbstractResolver):

    def __init__(self, dns_timeout=5, lookup=None):
        if (
            isinstance(dns_timeout, bool)
            or not isinstance(dns_timeout, (int, float))
            or not math.isfinite(dns_timeout)
            or dns_timeout <= 0
        ):
            raise ValueError(
                "DNS timeout must be a positive finite number"
            )

        if lookup is not None and not callable(lookup):
            raise ValueError("DNS lookup must be callable")

        self.dns_timeout = float(dns_timeout)
        self.lookup = lookup

    async def resolve(
        self,
        host,
        port=0,
        family=socket.AF_UNSPEC
    ):
        if (
            not isinstance(host, str)
            or not host
            or any(
                char.isspace()
                or ord(char) < 32
                or ord(char) == 127
                for char in host
            )
            or "%" in host
        ):
            raise OSError("Invalid DNS hostname")

        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 0 <= port <= 65535
        ):
            raise OSError("Invalid DNS port")

        if (
            isinstance(family, bool)
            or not isinstance(family, int)
            or family not in (
                socket.AF_UNSPEC,
                socket.AF_INET,
                socket.AF_INET6
            )
        ):
            raise OSError("Unsupported requested address family")

        try:
            loop = asyncio.get_running_loop()

            if self.lookup is not None:
                results = await asyncio.wait_for(
                    self.lookup(host, port, family),
                    timeout=self.dns_timeout
                )
            else:
                results = await asyncio.wait_for(
                    loop.getaddrinfo(
                        host,
                        port,
                        family=family,
                        type=socket.SOCK_STREAM
                    ),
                    timeout=self.dns_timeout
                )

        except asyncio.TimeoutError as error:
            raise OSError(
                "DNS resolution timed out"
            ) from error

        except OSError as error:
            raise OSError(
                f"DNS resolution failed: {error}"
            ) from error

        if not isinstance(results, (list, tuple)):
            raise OSError("DNS returned an invalid results format")

        if not results:
            raise OSError("DNS returned no addresses")

        records = []
        seen = set()

        for result in results:
            try:
                if (
                    not isinstance(result, (list, tuple))
                    or len(result) != 5
                ):
                    raise ValueError("Invalid DNS record structure")

                (
                    record_family,
                    socktype,
                    proto,
                    flags,
                    sockaddr
                ) = result

                if (
                    isinstance(record_family, bool)
                    or not isinstance(record_family, int)
                    or record_family not in (
                        socket.AF_INET,
                        socket.AF_INET6
                    )
                ):
                    raise ValueError("Unsupported address family")

                if (
                    isinstance(socktype, bool)
                    or not isinstance(socktype, int)
                    or socktype != socket.SOCK_STREAM
                ):
                    raise ValueError("Invalid socket type")

                if (
                    isinstance(proto, bool)
                    or not isinstance(proto, int)
                    or proto not in (0, socket.IPPROTO_TCP)
                ):
                    raise ValueError("Invalid socket protocol")

                # Some platforms return an empty string when no
                # getaddrinfo flags are set. Normalize it to zero.
                if flags == "":
                    flags = 0

                if (
                    isinstance(flags, bool)
                    or not isinstance(flags, int)
                    or flags < 0
                ):
                    raise ValueError("Invalid DNS flags")

                if not isinstance(sockaddr, (list, tuple)):
                    raise ValueError("Invalid socket address")

                expected_length = (
                    2 if record_family == socket.AF_INET else 4
                )

                if len(sockaddr) != expected_length:
                    raise ValueError("Invalid socket address length")

                address = sockaddr[0]
                address_port = sockaddr[1]

                if not isinstance(address, str):
                    raise ValueError("Invalid DNS address")

                if (
                    isinstance(address_port, bool)
                    or not isinstance(address_port, int)
                    or address_port != port
                ):
                    raise ValueError("DNS port mismatch")

                ip = ipaddress.ip_address(address)

                if (
                    record_family == socket.AF_INET
                    and ip.version != 4
                ):
                    raise ValueError("Address family mismatch")

                if (
                    record_family == socket.AF_INET6
                    and ip.version != 6
                ):
                    raise ValueError("Address family mismatch")

                if record_family == socket.AF_INET6:
                    flowinfo = sockaddr[2]
                    scope_id = sockaddr[3]

                    if (
                        isinstance(flowinfo, bool)
                        or not isinstance(flowinfo, int)
                        or flowinfo < 0
                        or isinstance(scope_id, bool)
                        or not isinstance(scope_id, int)
                        or scope_id != 0
                    ):
                        raise ValueError(
                            "Invalid IPv6 socket metadata"
                        )

            except (ValueError, IndexError, TypeError) as error:
                raise OSError(
                    "DNS returned an invalid address record"
                ) from error

            allowed, reason = NetworkSafety.validate_ip(str(ip))

            if not allowed:
                raise OSError(
                    f"DNS safety check failed: {reason}"
                )

            key = (str(ip), record_family)

            if key in seen:
                continue

            seen.add(key)

            records.append({
                "hostname": host,
                "host": str(ip),
                "port": port,
                "family": record_family,
                "proto": proto,
                "flags": flags
            })

        if not records:
            raise OSError("DNS returned no usable addresses")

        return records

    async def close(self):
        pass
