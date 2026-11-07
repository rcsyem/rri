import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit


class ScopeEngine:
    """Runtime target scope. Empty scope always fails closed."""

    def __init__(self, target=None, config_path=None):
        if isinstance(target, Path) and config_path is None:
            config_path = target
            target = None

        if target is not None and config_path is not None:
            raise ValueError("Specify target or config_path, not both")

        self.config_path = Path(config_path) if config_path is not None else None

        if config_path is not None:
            self.assets = self._load_scope()
        elif target is not None:
            self.assets = [self._asset_from_target(target)]
        else:
            self.assets = []

    @staticmethod
    def _normalize_domain(domain):
        if not isinstance(domain, str) or not domain:
            raise ValueError("Invalid domain")

        if domain != domain.strip():
            raise ValueError("Whitespace in domain")

        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in domain):
            raise ValueError("Invalid character in domain")

        if domain.endswith("."):
            domain = domain[:-1]

        try:
            domain = domain.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError("Invalid internationalized domain") from error

        if not domain or len(domain) > 253:
            raise ValueError("Invalid domain length")

        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            raise ValueError("IP addresses are not allowed as domains")

        for label in domain.split("."):
            if (
                not label
                or len(label) > 63
                or not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                    label
                )
            ):
                raise ValueError("Invalid domain syntax")

        return domain

    @staticmethod
    def _validate_path(path):
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or "%" in path
            or "\\" in path
            or "?" in path
            or "#" in path
            or "//" in path
            or any(ord(c) < 32 or ord(c) == 127 for c in path)
            or any(part in (".", "..") for part in path.split("/"))
        ):
            raise ValueError(f"Invalid authorized path: {path}")

    @staticmethod
    def _validate_raw_url(target):
        if not isinstance(target, str) or not target:
            raise ValueError("Invalid target URL")

        if target != target.strip():
            raise ValueError("Whitespace around URL is not allowed")

        if any(
            c.isspace() or ord(c) < 32 or ord(c) == 127
            for c in target
        ):
            raise ValueError("Whitespace or control character in URL")

        if "\\" in target:
            raise ValueError("Backslashes in URL are not allowed")

        if "#" in target:
            raise ValueError("URL fragments are not allowed")

    @classmethod
    def _asset_from_target(cls, target):
        cls._validate_raw_url(target)

        try:
            parsed = urlsplit(target)

            if (
                parsed.scheme.lower() not in ("http", "https")
                or not parsed.netloc
                or not parsed.hostname
            ):
                raise ValueError("Target must be an absolute HTTP(S) URL")

            scheme = parsed.scheme.lower()

            if parsed.username is not None or parsed.password is not None:
                raise ValueError("Credentials in URLs are not allowed")

            port = parsed.port

            if scheme == "https" and port not in (None, 443):
                raise ValueError("Unauthorized HTTPS port")

            if scheme == "http" and port not in (None, 80):
                raise ValueError("Unauthorized HTTP port")

            hostname = cls._normalize_domain(parsed.hostname)
            cls._validate_path(parsed.path or "/")

        except (AttributeError, TypeError) as error:
            raise ValueError("Malformed or unsafe target URL") from error

        return {
            "domain": hostname,
            "include_subdomains": False,
            "allowed_paths": ["/"],
        }

    def _load_scope(self):
        if self.config_path is None or not self.config_path.exists():
            raise FileNotFoundError("Scope configuration not found")

        with self.config_path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            raise ValueError("Invalid scope configuration")

        assets = data.get("authorized_assets")

        if not isinstance(assets, list) or not assets:
            raise ValueError("Invalid authorized_assets configuration")

        validated_assets = []

        for asset in assets:
            if not isinstance(asset, dict):
                raise ValueError("Invalid asset configuration")

            domain = self._normalize_domain(asset.get("domain"))
            paths = asset.get("allowed_paths", ["/"])

            if not isinstance(paths, list) or not paths:
                raise ValueError("Invalid allowed_paths configuration")

            for path in paths:
                self._validate_path(path)

            include_subdomains = asset.get("include_subdomains", False)

            if not isinstance(include_subdomains, bool):
                raise ValueError("include_subdomains must be boolean")

            validated_assets.append({
                "domain": domain,
                "include_subdomains": include_subdomains,
                "allowed_paths": list(dict.fromkeys(paths)),
            })

        return validated_assets

    def check(self, target):
        try:
            self._validate_raw_url(target)
            parsed = urlsplit(target)

            scheme = parsed.scheme.lower()

            if scheme not in ("http", "https"):
                return False, "Unsupported URL scheme"

            if not parsed.netloc or not parsed.hostname:
                return False, "Invalid target URL"

            if parsed.username is not None or parsed.password is not None:
                return False, "Credentials in URLs are not allowed"

            port = parsed.port

            if scheme == "https" and port not in (None, 443):
                return False, "Unauthorized HTTPS port"

            if scheme == "http" and port not in (None, 80):
                return False, "Unauthorized HTTP port"

            hostname = self._normalize_domain(parsed.hostname)
            path = parsed.path or "/"
            self._validate_path(path)

        except (ValueError, AttributeError, TypeError):
            return False, "Malformed or unsafe URL"

        matched_domain = False

        for asset in self.assets:
            domain = asset["domain"]
            domain_match = hostname == domain

            if asset["include_subdomains"]:
                domain_match = (
                    domain_match
                    or hostname.endswith("." + domain)
                )

            if not domain_match:
                continue

            matched_domain = True

            if (
                "/" in asset["allowed_paths"]
                or path in asset["allowed_paths"]
            ):
                return True, "Authorized domain and path match"

        if matched_domain:
            return False, "Path is outside authorized scope"

        return False, "Domain is outside authorized scope"
