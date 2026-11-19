"""Destination policy of the egress proxy: which host names, ports and addresses are allowed.

Host names: exact, case-insensitive matches against the allowlist. No wildcards, no IP
literals, no trailing-dot tricks, no userinfo, no internal Docker service names (they are simply
not on the list).

Addresses: every address a name resolves to must be public. Refused: private (RFC 1918, ULA),
loopback, link-local (including the 169.254.169.254 cloud metadata service), carrier-grade NAT,
multicast, reserved, unspecified, benchmarking and documentation ranges, and IPv6 transition
ranges that can embed an internal IPv4 address (IPv4-mapped, NAT64, 6to4, Teredo).
"""

import ipaddress
import re
from dataclasses import dataclass

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

# Explicit deny ranges, checked in addition to ipaddress' is_global (defense in depth).
_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/32",
        "2001:db8::/32",
        "2002::/16",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    )
)


class Denied(Exception):  # noqa: N818 - a policy decision, not a crash
    """The destination is not allowed. `reason` is safe to log and return."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def is_public_address(raw: str) -> bool:
    try:
        ip = ipaddress.ip_address(raw.split("%", 1)[0])
    except ValueError:
        return False
    if any(ip in net for net in _BLOCKED_NETWORKS if net.version == ip.version):
        return False
    return bool(
        ip.is_global
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_unspecified
    )


def normalize_host(raw: str) -> str:
    """Lower-cased DNS name, or Denied. IP literals and malformed names are refused."""
    host = raw.strip().lower()
    if not host or len(host) > 253 or host.endswith(".") or "@" in host:
        raise Denied("malformed host name")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise Denied("IP address targets are not allowed")
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise Denied("malformed host name")
    return host


@dataclass(frozen=True)
class Policy:
    allowed_hosts: frozenset[str]
    allowed_ports: frozenset[int] = frozenset({443})

    @classmethod
    def from_lists(cls, hosts: list[str], ports: list[int] | None = None) -> "Policy":
        normalized = frozenset(normalize_host(h) for h in hosts if h.strip())
        if not normalized:
            raise ValueError("the egress allowlist is empty")
        return cls(normalized, frozenset(ports or [443]))

    def check_target(self, host: str, port: int) -> str:
        """Return the normalized host if the (host, port) target may be tunneled."""
        name = normalize_host(host)
        if port not in self.allowed_ports:
            raise Denied("port is not allowed (HTTPS on 443 only)")
        if name not in self.allowed_hosts:
            raise Denied("host is not on the egress allowlist")
        return name

    @staticmethod
    def check_addresses(addresses: list[str]) -> list[str]:
        """All resolved addresses must be public; returns them in order, without duplicates."""
        if not addresses:
            raise Denied("the host name did not resolve")
        bad = [a for a in addresses if not is_public_address(a)]
        if bad:
            raise Denied("the host name resolves to a non-public address")
        seen: list[str] = []
        for a in addresses:
            if a not in seen:
                seen.append(a)
        return seen
