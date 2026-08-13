"""Generate an OCI runtime bundle (rootfs + config.json) from a Policy.

Ported from the verified spike (scripts/gvisor_spike.py). The rootfs reuses the host's
`/usr` read-only via bind mounts + usrmerge symlinks; policy.read/write paths are added
as binds. Writes are made ephemeral by gVisor's `--overlay2=all:memory` (set by the
backend, not here), so even rw binds never touch the host.
"""
from __future__ import annotations

import json
import os

from ..policy import Policy

# usrmerge: on modern Ubuntu these are symlinks into /usr; recreate the symlink in the
# rootfs and bind the real dirs (/usr, /etc) below.
_USRMERGE = ("bin", "sbin", "lib", "lib64")
_ROOT_BINDS = ("usr", "etc")

_MINIMAL_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8"}


def build_rootfs(bundle_dir: str) -> str:
    rootfs = os.path.join(bundle_dir, "rootfs")
    os.makedirs(rootfs, exist_ok=True)
    for name in _USRMERGE:
        src = "/" + name
        dst = os.path.join(rootfs, name)
        if os.path.islink(src):
            os.symlink(os.readlink(src), dst)
        elif os.path.isdir(src):
            os.makedirs(dst, exist_ok=True)  # real dir → bind target (added in _mounts)
    for d in (*_ROOT_BINDS, "proc", "tmp", "dev"):
        os.makedirs(os.path.join(rootfs, d), exist_ok=True)
    return rootfs


def _mounts(policy: Policy, *, host_system: bool) -> list[dict]:
    mounts: list[dict] = [
        {"destination": "/proc", "type": "proc", "source": "proc"},
        {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
         "options": ["nosuid", "nodev", "mode=1777"]},
        {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
         "options": ["nosuid", "mode=0755"]},
    ]
    # host-bind base only: expose the host's read-only /usr,/etc (+ real bin/sbin/lib).
    # In image mode the image rootfs already provides these (writable), so skip them.
    if host_system:
        for name in _ROOT_BINDS:
            src = "/" + name
            if os.path.isdir(src):
                mounts.append({"destination": src, "source": src, "type": "bind",
                               "options": ["rbind", "ro"]})
        for name in _USRMERGE:  # only real dirs, not usrmerge symlinks
            src = "/" + name
            if os.path.isdir(src) and not os.path.islink(src):
                mounts.append({"destination": src, "source": src, "type": "bind",
                               "options": ["rbind", "ro"]})
    # read/write sugar: same-path disk binds (read = ro, write = durable rw to host).
    for path in policy.read:
        mounts.append({"destination": path, "source": path, "type": "bind",
                       "options": ["rbind", "ro"]})
    for path in policy.write:
        mounts.append({"destination": path, "source": path, "type": "bind",
                       "options": ["rbind", "rw"]})
    # explicit provider-backed volumes (memory / disk / fsspec / custom).
    for m in policy.mounts:
        mounts.append(m.oci_mount())
    return mounts


def _env(policy: Policy, extra: dict[str, str] | None) -> list[str]:
    env = dict(_MINIMAL_ENV)            # D8: minimal; host env is NOT inherited
    if extra:
        env.update(extra)
    return [f"{k}={v}" for k, v in env.items()]


def _rlimits(policy: Policy) -> list[dict]:
    return [
        {"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024},
        {"type": "RLIMIT_NPROC", "hard": policy.max_processes, "soft": policy.max_processes},
        {"type": "RLIMIT_CPU", "hard": policy.max_cpu_seconds, "soft": policy.max_cpu_seconds},
    ]


def make_config(policy: Policy, init_cmd: list[str], env: dict[str, str] | None,
                *, root_path: str, host_system: bool) -> dict:
    return {
        "ociVersion": "1.0.0",
        "process": {
            "terminal": False,
            "user": {"uid": 0, "gid": 0},
            "args": list(init_cmd),
            "env": _env(policy, env),
            "cwd": "/",
            "capabilities": {k: [] for k in
                             ("bounding", "effective", "inheritable", "permitted", "ambient")},
            "rlimits": _rlimits(policy),
        },
        # writable root so tooling (pip/npm/builds) works; --overlay2=root:memory keeps
        # those writes ephemeral in RAM and off the host (verified). In image mode the
        # root is the runner-owned image rootfs (so /usr,/etc are writable too).
        "root": {"path": root_path, "readonly": False},
        "hostname": "temenos",
        "mounts": _mounts(policy, host_system=host_system),
        "linux": {
            # Drop the network namespace for anything but network='none', so the box
            # shares the host netns; keep it (isolated, empty) otherwise. Pairs with the
            # backend's --network=host|none (both are required — verified).
            # 'filtered' shares the netns too: the proxy it is pointed at listens on the
            # host's loopback, and a box in its own empty namespace could not reach it.
            # That sharing is also exactly why filtered is cooperative — see plan §13.
            "namespaces": [{"type": t} for t in
                           (("pid", "mount", "ipc", "uts") if policy.network != "none"
                            else ("pid", "mount", "ipc", "uts", "network"))],
            # Harmless under rootless --ignore-cgroups; real enforcement is the systemd
            # scope the backend wraps the box in (D6).
            "resources": {"memory": {"limit": policy.max_memory_mb * 1024 * 1024}},
        },
    }


def build_bundle(
    policy: Policy,
    bundle_dir: str,
    *,
    init_cmd: tuple[str, ...] = ("/bin/sleep", "infinity"),
    env: dict[str, str] | None = None,
    image_rootfs: str | None = None,
) -> None:
    """Write config.json (and, for the host-bind base, rootfs/) into `bundle_dir`.

    image_rootfs set -> image mode: root is the runner-owned image rootfs (writable
    /usr,/etc); no host system binds. Otherwise -> host-bind base: a scaffold rootfs in
    the bundle + read-only host /usr,/etc.
    """
    if image_rootfs:
        cfg = make_config(policy, list(init_cmd), env,
                          root_path=os.path.abspath(image_rootfs), host_system=False)
    else:
        build_rootfs(bundle_dir)
        cfg = make_config(policy, list(init_cmd), env,
                          root_path="rootfs", host_system=True)
    with open(os.path.join(bundle_dir, "config.json"), "w") as f:
        json.dump(cfg, f, indent=2)
