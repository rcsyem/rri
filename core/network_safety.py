import ipaddress
import socket


class NetworkSafety:

    @staticmethod
    def validate_ip(address):

        if not isinstance(address, str) or not address:
            return False, "Invalid IP address"

        if "%" in address:
            return False, "IPv6 zone identifiers are not allowed"

        try:
            ip = ipaddress.ip_address(address)

        except ValueError:
            return False, "Invalid IP address"

        # Evaluate IPv4-mapped IPv6 using its embedded IPv4 address.
        if isinstance(ip, ipaddress.IPv6Address):
            mapped = ip.ipv4_mapped

            if mapped is not None:
                ip = mapped

        if not ip.is_global:
            return False, f"Non-public IP address blocked: {ip}"

        return True, "Public IP address accepted"

    @classmethod
    def validate_dns_results(cls, addresses):

        if not isinstance(addresses, (list, tuple, set)):
            return False, "Invalid DNS results format"

        if not addresses:
            return False, "DNS returned no addresses"

        validated = []
        seen = set()

        for address in addresses:

            if not isinstance(address, str):
                return False, "DNS returned an invalid address"

            allowed, reason = cls.validate_ip(address)

            if not allowed:
                return False, reason

            try:
                ip = ipaddress.ip_address(address)

                if isinstance(ip, ipaddress.IPv6Address):
                    if ip.ipv4_mapped is not None:
                        ip = ip.ipv4_mapped

                normalized = str(ip)

            except ValueError:
                return False, "DNS returned an invalid address"

            if normalized not in seen:
                seen.add(normalized)
                validated.append(normalized)

        if not validated:
            return False, "DNS returned no usable addresses"

        return True, validated

    @classmethod
    def resolve_and_validate(cls, hostname):

        if not isinstance(hostname, str) or not hostname:
            return False, "Invalid hostname"

        try:
            results = socket.getaddrinfo(
                hostname,
                None,
                type=socket.SOCK_STREAM
            )

            addresses = [
                result[4][0]
                for result in results
            ]

        except (socket.gaierror, OSError):
            return False, "DNS resolution failed"

        return cls.validate_dns_results(addresses)
