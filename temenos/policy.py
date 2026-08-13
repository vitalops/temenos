"""Policy — the semantic layer (Layer 0, pure data, no OS calls).

A ``Policy`` describes what code executed inside a box may do. It is **frozen**
(immutable, hashable). The *filesystem* is locked down by default — ``Policy()`` grants no
host writes (overlay only) and tight resource limits — but **network defaults to full host
passthrough** in v1 (a deliberate convenience default; set ``network=False`` to isolate a
box, and do so for adversarial/multi-tenant workloads). You opt *in* to broader filesystem
and resource capability.

``restrict()`` is the only way to derive a child policy, and it can never widen a
capability — escalation raises ``PolicyViolation`` rather than being an operation.
"""
from __future__ import annotations

import posixpath
from dataclasses import dataclass

from .exceptions import PolicyViolation
from .storage import Mount


#: Network modes, ordered from least to most reach. `restrict()` may move a box
#: down this list and never up.
NETWORK_MODES: tuple[str, ...] = ("none", "filtered", "host")


class NetworkMode(str):
    """The mode, as a string that is still *false* when there is no network.

    v1 shipped ``network: bool`` and the natural way to read it was
    ``if policy.network:``. A plain string would keep that expression
    compiling and silently invert it — ``bool("none")`` is ``True`` — which is
    the worst kind of API change: nothing fails, and an isolated box starts
    being treated as a connected one. So truthiness keeps meaning exactly what
    it meant, and the third state is available to anyone who asks for it by
    name.
    """

    __slots__ = ()

    def __bool__(self) -> bool:
        return self != "none"


def _coerce_network(value: "bool | str") -> NetworkMode:
    """Three modes, and the v1 booleans still mean what they meant.

    ``False``/``'none'`` — no network at all (isolated netns).
    ``'filtered'``       — egress via the box's own allowlist proxy.
    ``True``/``'host'``  — full host passthrough, no filtering.

    Booleans are kept because they were the v1 API and a policy in somebody's
    config file should not stop parsing when this grew a third state.
    """
    if isinstance(value, bool):
        return NetworkMode("host" if value else "none")
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ("host", "on", "true", "yes"):
            return NetworkMode("host")
        if s in ("filtered", "proxy", "allowlist"):
            return NetworkMode("filtered")
        if s in ("none", "off", "false", "no", ""):
            return NetworkMode("none")
        raise ValueError(
            f"invalid network mode: {value!r} (use 'none' | 'filtered' | 'host')"
        )
    raise ValueError(
        f"network must be bool or 'none'/'filtered'/'host', got {type(value).__name__}"
    )


_SET_FIELDS = ("read", "write", "allow_hosts")
_INT_FIELDS = ("max_memory_mb", "max_cpu_seconds", "max_processes", "max_output_bytes")
_ALL_FIELDS = _SET_FIELDS + _INT_FIELDS + ("network",)


@dataclass(frozen=True)
class Policy:
    # Filesystem — HOST paths made visible inside the box, at the same path.
    # These are sugar for DiskVolume mounts: `read` = read-only disk bind, `write` =
    # durable read-write disk bind (writes persist to the host dir). For ephemeral
    # scratch use a MemoryVolume mount (or /tmp); for remapped/remote storage use `mounts`.
    read: tuple[str, ...] = ()
    write: tuple[str, ...] = ()

    # Explicit provider-backed volumes (memory / disk / fsspec / custom) at chosen paths.
    mounts: tuple[Mount, ...] = ()

    # Network — "none" | "filtered" | "host" (bools still accepted: False/True).
    # ⚠️ The "host" default gives every box full host network reach (localhost, LAN,
    # cloud metadata, arbitrary egress) with no filtering.
    # "filtered" routes egress through a per-box allowlist proxy (see `allow_hosts`
    # and temenos/net/). Read `network_enforced` before trusting it for adversarial
    # code: today the box is *pointed* at the proxy rather than confined to it.
    network: str = "host"  # a NetworkMode after __post_init__

    # Hosts reachable in "filtered" mode. Entries are `host` or `host:port`, and a
    # leading `*.` matches subdomains: ("*.acme.com", "api.stripe.com:443").
    # Empty means nothing is reachable, which is "none" with extra steps — that is a
    # coherent thing to configure and it is what a default-deny posture starts from.
    allow_hosts: tuple[str, ...] = ()

    # Box base image (a runner-owned rootfs under $TEMENOS_DATA/images/<name>). None =
    # default host-`/usr`-bind base (read-only system). An image gives a writable system
    # (pip/apt/npm) — see image.py.
    image: str | None = None

    # Root-overlay scratch medium: "disk" (default — disk-backed, **checkpointable**,
    # not RAM-bound) or "memory" (RAM — fast, but RAM-bound AND **cannot be
    # checkpointed**; opt-in, backend warns).
    scratch: str = "disk"

    # Filesystem persistence (D17): "auto" (background checkpoint loop + on close, the
    # default), "on-close" (commit only when the box closes — loop off), "off"
    # (--ephemeral-fs: never checkpoint, throwaway fs). The box dir's checkpoint is also
    # what a box restores from on next use. (memory scratch can't checkpoint → treated as off.)
    checkpoint: str = "auto"

    # Resource limits (enforced per-box via the systemd scope; see plan §9/D6).
    max_memory_mb: int = 256
    max_cpu_seconds: int = 30
    max_processes: int = 16
    max_output_bytes: int = 10 * 1024 * 1024  # 10 MiB

    def __post_init__(self) -> None:
        # Ergonomic API: accept lists; store frozen tuples (deduped order-preserving).
        for f in _SET_FIELDS:
            value = getattr(self, f)
            if isinstance(value, (str, bytes)):
                raise TypeError(f"{f} must be a sequence of strings, not {type(value).__name__}")
            object.__setattr__(self, f, tuple(dict.fromkeys(value)))
        object.__setattr__(self, "mounts", tuple(self.mounts))
        for m in self.mounts:
            if not isinstance(m, Mount):
                raise TypeError(f"mounts must contain Mount instances, got {type(m).__name__}")
        object.__setattr__(self, "network", _coerce_network(self.network))
        if self.allow_hosts and self.network != "filtered":
            raise ValueError(
                f"allow_hosts is only meaningful with network='filtered', "
                f"got network={self.network!r} — a host allowlist that nothing "
                f"consults reads like containment and is not"
            )
        if self.image is not None and not isinstance(self.image, str):
            raise TypeError(f"image must be a str name or None, got {type(self.image).__name__}")
        if self.scratch not in ("disk", "memory"):
            raise ValueError(f"scratch must be 'disk' or 'memory', got {self.scratch!r}")
        if self.checkpoint not in ("auto", "on-close", "off"):
            raise ValueError(f"checkpoint must be 'auto'|'on-close'|'off', got {self.checkpoint!r}")
        for f in _INT_FIELDS:
            v = getattr(self, f)
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise ValueError(f"{f} must be a non-negative int, got {v!r}")

    # -- deriving child policies ------------------------------------------------------

    def restrict(self, **changes: object) -> "Policy":
        """Return a new Policy no more capable than self — the only way to derive a child.

        - set fields (read/write/network): each new value must be a **subset** of self's
        - int fields: each new value must be **<=** self's

        Any widening raises ``PolicyViolation``. Fields not passed are inherited. There is
        no ``escalate()`` — widening is an error, not an operation.
        """
        unknown = set(changes) - set(_ALL_FIELDS)
        if unknown:
            raise TypeError(f"restrict() got unexpected field(s): {sorted(unknown)}")

        merged: dict[str, object] = {f: getattr(self, f) for f in _ALL_FIELDS}
        for field_name, value in changes.items():
            if field_name in _SET_FIELDS:
                if isinstance(value, (str, bytes)):
                    raise TypeError(f"{field_name} must be a sequence of strings")
                new = tuple(dict.fromkeys(value))  # type: ignore[arg-type]
                extra = set(new) - set(getattr(self, field_name))
                if extra:
                    raise PolicyViolation(
                        f"restrict() cannot widen {field_name}: {sorted(extra)} not in parent"
                    )
                merged[field_name] = new
            elif field_name in _INT_FIELDS:
                iv = int(value)  # type: ignore[call-overload]
                if iv > getattr(self, field_name):
                    raise PolicyViolation(
                        f"restrict() cannot raise {field_name}: {iv} > {getattr(self, field_name)}"
                    )
                merged[field_name] = iv
            else:  # network
                mode = _coerce_network(value)  # type: ignore[arg-type]
                if NETWORK_MODES.index(mode) > NETWORK_MODES.index(self.network):
                    raise PolicyViolation(
                        f"restrict() cannot widen network: {self.network!r} -> {mode!r}"
                    )
                merged[field_name] = mode
        # mounts and image are inherited unchanged (restrict narrows simple capabilities;
        # provider volumes and the base image are not subset-narrowed — see plan).
        # Narrowing the mode has to take the allowlist with it, or a child that
        # dropped to "none" would carry hosts nothing consults — and one that
        # narrowed *to* "filtered" from "host" starts from the parent's list.
        if merged["network"] != "filtered":
            merged["allow_hosts"] = ()
        merged["mounts"] = self.mounts
        merged["image"] = self.image
        merged["scratch"] = self.scratch
        merged["checkpoint"] = self.checkpoint
        return Policy(**merged)  # type: ignore[arg-type]

    # -- plain-data round trip (shared by REST/MCP/CLI/config) -----------------------

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "Policy":
        unknown = set(data) - set(_ALL_FIELDS) - {"mounts", "image", "scratch", "checkpoint"}
        if unknown:
            raise ValueError(f"unknown policy field(s): {sorted(unknown)}")
        kwargs: dict[str, object] = {}
        for f in _SET_FIELDS:
            if f in data:
                kwargs[f] = tuple(data[f])  # type: ignore[arg-type]
        for f in _INT_FIELDS:
            if f in data:
                kwargs[f] = int(data[f])  # type: ignore[call-overload]
        if "network" in data:
            kwargs["network"] = _coerce_network(data["network"])  # type: ignore[arg-type]
        if "mounts" in data:
            kwargs["mounts"] = tuple(Mount.from_dict(m) for m in data["mounts"])  # type: ignore[union-attr]
        if "image" in data:
            kwargs["image"] = data["image"]
        if "scratch" in data:
            kwargs["scratch"] = data["scratch"]
        if "checkpoint" in data:
            kwargs["checkpoint"] = data["checkpoint"]
        return cls(**kwargs)  # type: ignore[arg-type]

    def to_dict(self) -> dict[str, object]:
        return {
            "read": list(self.read),
            "write": list(self.write),
            "network": str(self.network),
            "allow_hosts": list(self.allow_hosts),
            "mounts": [m.to_dict() for m in self.mounts],
            "image": self.image,
            "scratch": self.scratch,
            "checkpoint": self.checkpoint,
            "max_memory_mb": self.max_memory_mb,
            "max_cpu_seconds": self.max_cpu_seconds,
            "max_processes": self.max_processes,
            "max_output_bytes": self.max_output_bytes,
        }

    # -- semantic checks (for validation/audit; gVisor mounts are the real enforcer) --

    def allows_path_read(self, path: str) -> bool:
        """True if ``path`` is under a read *or* write mount (writable implies readable)."""
        return self._under_any(path, self.read) or self._under_any(path, self.write)

    def allows_path_write(self, path: str) -> bool:
        return self._under_any(path, self.write)

    @staticmethod
    def _under_any(path: str, bases: tuple[str, ...]) -> bool:
        p = posixpath.normpath(path)
        for base in bases:
            nb = posixpath.normpath(base)
            if p == nb or p.startswith(nb.rstrip("/") + "/"):
                return True
        return False
