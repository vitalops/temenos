"""Which hosts a filtered box may reach — pure data, no sockets.

The vocabulary is deliberately small, because an allowlist somebody cannot
read is an allowlist somebody gets wrong:

    acme.com            that host, any port
    *.acme.com          any subdomain, any port (and not `acme.com` itself)
    api.stripe.com:443  that host, that port only

Everything else is refused. There is no negation, no regex, and no ordering —
a list of names either contains what you asked for or it doesn't. Denial is
the default and the only thing that opens it is an entry somebody wrote.

**IP literals are refused unless listed exactly.** A box asking for
``169.254.169.254`` is asking for cloud credentials, and a box asking for
``127.0.0.1`` is asking for whatever the host runs on loopback. Naming an
address explicitly is still allowed — a deployment whose partner is an IP
knows what it is doing — but it cannot be reached through a wildcard.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

#: The addresses worth naming, though the private-space check catches most of
#: them anyway. Kept explicit because the *reason* belongs in the refusal.
METADATA_ADDRESSES = frozenset({
    "169.254.169.254",   # AWS / GCP / Azure
    "100.100.100.200",   # Alibaba
    "fd00:ec2::254",     # AWS IMDSv2 over IPv6
})


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.allowed


class HostAllowlist:
    """A parsed allowlist, and the one function that judges against it."""

    __slots__ = ("entries", "_exact", "_suffix")

    def __init__(self, entries: "tuple[str, ...] | list[str]" = ()) -> None:
        self.entries = tuple(entries)
        # (host, port|None) pairs, split by kind so matching is a dict lookup
        # and a short loop rather than a scan with parsing in it.
        self._exact: set[tuple[str, int | None]] = set()
        self._suffix: set[tuple[str, int | None]] = set()
        for raw in self.entries:
            host, port = _split(raw)
            if host.startswith("*."):
                self._suffix.add((host[2:], port))
            else:
                self._exact.add((host, port))

    def __bool__(self) -> bool:
        return bool(self.entries)

    def check(self, host: str, port: int) -> Verdict:
        """Whether a box may connect to ``host:port``."""
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return Verdict(False, "no host")

        literal = _as_ip(host)
        if literal is not None:
            # An address is reachable only if somebody wrote that address. A
            # wildcard is about names and must never resolve into private
            # space by accident.
            if (host, port) in self._exact or (host, None) in self._exact:
                return Verdict(True)
            if host in METADATA_ADDRESSES:
                return Verdict(False, f"{host} is a cloud metadata address")
            if _is_private(literal):
                return Verdict(False, f"{host} is private or link-local space")
            return Verdict(False, f"{host} is not in the allowlist")

        if (host, port) in self._exact or (host, None) in self._exact:
            return Verdict(True)
        for base, allowed_port in self._suffix:
            if allowed_port is not None and allowed_port != port:
                continue
            if host.endswith("." + base):
                return Verdict(True)
        return Verdict(False, f"{host}:{port} is not in the allowlist")


def _split(entry: str) -> tuple[str, int | None]:
    """``host`` or ``host:port`` → (host, port|None). IPv6 needs brackets."""
    raw = entry.strip().lower().rstrip(".")
    if raw.startswith("["):  # [::1]:443
        close = raw.find("]")
        if close == -1:
            raise ValueError(f"unterminated IPv6 literal in allowlist entry: {entry!r}")
        host, rest = raw[1:close], raw[close + 1 :]
        port = int(rest[1:]) if rest.startswith(":") else None
        return host, port
    if raw.count(":") == 1:
        host, _, port_text = raw.partition(":")
        try:
            return host, int(port_text)
        except ValueError as exc:
            raise ValueError(f"bad port in allowlist entry {entry!r}") from exc
    return raw, None


def _as_ip(host: str) -> "ipaddress._BaseAddress | None":
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _is_private(address: "ipaddress._BaseAddress") -> bool:
    """`is_private` already covers loopback, RFC 1918, link-local and the
    unspecified address; multicast is the one category it misses."""
    return address.is_private or address.is_multicast


__all__ = ["METADATA_ADDRESSES", "HostAllowlist", "Verdict"]
