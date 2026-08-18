from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import urlparse


IPV4_OR_NETWORK = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])"
)
URL_PATTERN = re.compile(r"(?i)\bhttps?://[^\s'\"<>]+")
DOMAIN_PATTERN = re.compile(
    r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?![\w.-])"
)


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    blocked_targets: list[str]


class ScopeGuard:
    """Match observed targets against explicit IP, network, or domain scopes."""

    def __init__(self, entries: list[str]):
        if not entries:
            raise ValueError("At least one authorized scope entry is required")

        self.networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.domains: list[str] = []

        for raw_entry in entries:
            entry = raw_entry.strip()
            if not entry or entry.startswith("#"):
                continue
            self._add_entry(entry)

        if not self.networks and not self.domains:
            raise ValueError("No valid scope entries were supplied")

    def _add_entry(self, entry: str) -> None:
        hostname = self._hostname(entry) if "://" in entry else None
        candidate = hostname or entry

        try:
            if "/" in candidate:
                self.networks.append(ipaddress.ip_network(candidate, strict=False))
            else:
                address = ipaddress.ip_address(candidate)
                self.networks.append(
                    ipaddress.ip_network(
                        f"{address}/{address.max_prefixlen}", strict=False
                    )
                )
            return
        except ValueError:
            pass

        domain = candidate.lower().rstrip(".")
        if domain.startswith("*."):
            domain = domain[2:]
        if not DOMAIN_PATTERN.fullmatch(domain):
            raise ValueError(f"Invalid scope entry: {entry}")
        self.domains.append(domain)

    @staticmethod
    def _hostname(value: str) -> str | None:
        parsed_value = value if "://" in value else f"//{value}"
        try:
            return urlparse(parsed_value).hostname
        except ValueError:
            return None

    def is_allowed(self, target: str) -> bool:
        hostname = self._hostname(target) if "://" in target else target
        hostname = hostname.strip().strip("[]").lower().rstrip(".")

        try:
            if "/" in hostname:
                target_network = ipaddress.ip_network(hostname, strict=False)
                return any(
                    target_network.version == allowed.version
                    and target_network.subnet_of(allowed)
                    for allowed in self.networks
                )

            target_ip = ipaddress.ip_address(hostname)
            return any(target_ip in network for network in self.networks)
        except ValueError:
            return any(
                hostname == domain or hostname.endswith(f".{domain}")
                for domain in self.domains
            )

    def check(self, targets: list[str]) -> ScopeDecision:
        blocked = [target for target in targets if not self.is_allowed(target)]
        return ScopeDecision(allowed=not blocked, blocked_targets=blocked)

    @staticmethod
    def extract_targets(text: str) -> list[str]:
        targets: list[str] = []

        for url in URL_PATTERN.findall(text):
            hostname = ScopeGuard._hostname(url)
            if hostname:
                targets.append(hostname)

        targets.extend(IPV4_OR_NETWORK.findall(text))
        targets.extend(DOMAIN_PATTERN.findall(text))

        ignored = {"localhost"}
        file_suffixes = {
            ".csv",
            ".html",
            ".json",
            ".log",
            ".lst",
            ".txt",
            ".xml",
            ".yaml",
            ".yml",
        }
        unique: list[str] = []
        for target in targets:
            normalized = target.lower().rstrip(".,;:")
            if (
                normalized in ignored
                or any(normalized.endswith(suffix) for suffix in file_suffixes)
                or normalized in unique
            ):
                continue
            unique.append(normalized)
        return unique
