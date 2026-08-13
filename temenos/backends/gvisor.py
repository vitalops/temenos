"""GVisorBackend — the v1 isolation engine (verified by scripts/gvisor_spike.py).

Session contract (held-foreground pattern, since rootless can't `create`+`start`):
  open()  -> `[systemd-run --user --scope ...] runsc <run-globals> run -bundle B <cid>`
             held as a child process (init `sleep infinity`); poll until "running".
  exec()  -> `runsc <exec-globals> exec [-cwd][-env] <cid> -- <cmd>`.
  close() -> `runsc kill <cid> KILL`; reap held child; `runsc delete --force`; cleanup.

Key flags: `--overlay2=root:dir=<box dir>` (disk-backed, checkpointable; `root:memory`
only for scratch='memory'), `--network=none|host` (D3), `--platform` auto-detected
(kvm→systrap→ptrace), and a per-box `systemd-run --user --scope` for enforced memory (D6).
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
import uuid

from ..exceptions import BackendError
from ..policy import Policy
from ..result import ExecResult
from . import oci
from .base import Backend

log = logging.getLogger("temenos.gvisor")

_PLATFORMS = ("kvm", "systrap", "ptrace")
_START_TIMEOUT_S = 10.0


class GVisorBackend(Backend):
    name = "gvisor"
    _platform_cache: str | None = None

    def __init__(self, *, runsc: str = "runsc", work_dir: str | None = None) -> None:
        # work_dir: put state/bundle/overlay under this box data dir (D16,
        # everything-in-.temenos). None → ephemeral temp dirs.
        self._runsc = runsc
        self._work_dir = work_dir
        self._cid: str | None = None
        self._bundle: str | None = None
        self._state: str | None = None
        self._overlay_dir: str | None = None
        self._held: subprocess.Popen | None = None
        self._policy: Policy | None = None
        self._base_env: dict[str, str] = {}
        self._proxy = None  # RunningProxy for network='filtered' boxes

    # -- availability / platform detection -------------------------------------------

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("runsc") is not None and cls.detect_platform() is not None

    @classmethod
    def detect_platform(cls, runsc: str = "runsc") -> str | None:
        """First gVisor platform that actually starts /bin/true (cached). Probe, don't
        trust `runsc help` — all platforms list even when they fail to start (e.g. kvm
        without /dev/kvm, systrap on WSL2)."""
        if cls._platform_cache is not None:
            return cls._platform_cache
        if shutil.which(runsc) is None:
            return None
        for plat in _PLATFORMS:
            state = tempfile.mkdtemp(prefix="temenos-plat-")
            bundle = tempfile.mkdtemp(prefix="temenos-platb-")
            try:
                oci.build_bundle(Policy(), bundle, init_cmd=("/bin/true",))
                g = [runsc, f"--root={state}", "--rootless", "--network=none",
                     "--ignore-cgroups", f"--platform={plat}"]
                r = subprocess.run(g + ["run", "-bundle", bundle, f"plat-{plat}"],
                                   capture_output=True, timeout=30)
                subprocess.run(g + ["delete", "--force", f"plat-{plat}"],
                               capture_output=True)
                if r.returncode == 0:
                    cls._platform_cache = plat
                    return plat
            except Exception:  # noqa: BLE001 — a broken platform shouldn't abort detection
                pass
            finally:
                shutil.rmtree(state, ignore_errors=True)
                shutil.rmtree(bundle, ignore_errors=True)
        return None

    # -- flag construction ------------------------------------------------------------

    def _net_mode(self) -> str:
        """What `runsc --network` gets: `host` or `none`, and nothing else.

        `filtered` is `host` at this layer plus a proxy the box is pointed at.
        runsc has no third mode to ask for — confining the box *to* the proxy
        is a network namespace built around it (plan §13), which is why
        `EgressProxy.enforced` says False.
        """
        if self._policy is None or self._policy.network == "none":
            return "none"
        return "host"

    def _overlay2(self) -> str:
        # disk (default): root overlay backed on disk → not RAM-bound AND checkpointable.
        # memory (opt-in): RAM-backed → fast but RAM-bound and CANNOT be checkpointed.
        if self._policy and self._policy.scratch == "memory":
            log.warning("box %s: scratch='memory' — writes are RAM-bound and this box "
                        "CANNOT be checkpointed (fscheckpoint needs a disk-backed overlay). "
                        "Use scratch='disk' (default) for checkpointable boxes.", self._cid)
            return "root:memory"
        return f"root:dir={self._overlay_dir}"

    def _run_globals(self, platform: str) -> list[str]:
        return [self._runsc, f"--root={self._state}", "--rootless", f"--network={self._net_mode()}",
                "--ignore-cgroups", f"--overlay2={self._overlay2()}", f"--platform={platform}"]

    def _ctl_globals(self) -> list[str]:
        # exec/state/kill/delete join the running sandbox; no --overlay2 needed.
        return [self._runsc, f"--root={self._state}", "--rootless", f"--network={self._net_mode()}",
                "--ignore-cgroups", f"--platform={self._platform_cache}"]

    @staticmethod
    def _scope_prefix(policy: Policy) -> list[str]:
        """Per-box systemd user scope for enforced MEMORY (D6, spike-verified). Empty if
        unavailable. Note: the scope bounds the whole sandbox host-side (sentry + gofer +
        guest), so we do NOT set TasksMax here — gVisor's sentry needs many host threads;
        guest process count is bounded inside the box via OCI RLIMIT_NPROC instead."""
        if shutil.which("systemd-run") is None or not os.environ.get("XDG_RUNTIME_DIR"):
            log.warning("systemd-run --user unavailable: per-box memory limits will NOT "
                        "be enforced (D6). Do not run adversarial multi-tenant.")
            return []
        return [
            "systemd-run", "--user", "--scope", "-q",
            "-p", f"MemoryMax={policy.max_memory_mb}M",
            "-p", "MemorySwapMax=0",
            "--",
        ]

    # -- lifecycle --------------------------------------------------------------------

    def open(self, policy: Policy, *, name: str, env: dict[str, str] | None = None,
             restore_from: str | None = None) -> None:
        if self._held is not None:
            raise BackendError("backend already open")
        if restore_from and policy.scratch == "memory":
            raise BackendError("restore needs a disk-backed overlay; use scratch='disk'")
        if restore_from and not os.path.isdir(restore_from):
            raise BackendError(f"restore checkpoint dir not found: {restore_from!r}")
        if policy.network == "host":
            log.warning("box %s: network=host (full passthrough, NO firewalling) — the "
                        "box can reach localhost, the LAN, cloud metadata, and exfiltrate "
                        "anywhere. Operator opt-in only; unsafe for adversarial tenants.",
                        name)
        elif policy.network == "filtered":
            log.warning("box %s: network=filtered is COOPERATIVE, not enforced — the box "
                        "is pointed at an allowlist proxy via HTTPS_PROXY, which every "
                        "well-behaved client honours and hostile code ignores. It stops "
                        "an agent's tools and `pip` reaching the wrong host; it does not "
                        "contain an attacker. For that, still network='none'. (Enforcing "
                        "it needs pasta + nft TPROXY — plan.md §13.)", name)
        # read paths must already exist (host data we expose). write paths are durable
        # disk binds — created if missing (the box's output dir). Box-internal scratch
        # should use the always-present /tmp or a MemoryVolume.
        for path in policy.read:
            if not os.path.exists(path):
                raise BackendError(
                    f"read path does not exist on host: {path!r} "
                    "(read paths must be existing host paths; use /tmp for scratch)"
                )
        for path in policy.write:
            os.makedirs(path, exist_ok=True)
        platform = self.detect_platform(self._runsc)
        if platform is None:
            raise BackendError("no usable gVisor platform (need runsc + kvm/systrap/ptrace)")

        self._policy = policy
        self._base_env = dict(env or {})
        if policy.network == "filtered":
            # Started before the box so its address exists to be injected: a
            # box whose HTTPS_PROXY points at an unbound port fails its first
            # request with a connection refused nobody can explain.
            from ..net.runner import start_proxy

            self._proxy = start_proxy(policy.allow_hosts, box=name)
            self._base_env.update(self._proxy.env())
            log.info("box %s: egress via %s (%d allowed)", name, self._proxy.url,
                     len(policy.allow_hosts))
        self._cid = name or f"temenos-{uuid.uuid4().hex[:12]}"
        if self._work_dir:
            os.makedirs(self._work_dir, exist_ok=True)
            self._state = os.path.join(self._work_dir, "state")
            self._bundle = os.path.join(self._work_dir, "bundle")
        else:
            self._state = tempfile.mkdtemp(prefix="temenos-state-")
            self._bundle = tempfile.mkdtemp(prefix="temenos-bundle-")
        self._overlay_dir = os.path.join(self._state, "overlay")  # disk-backed root upper
        for d in (self._state, self._bundle, self._overlay_dir):
            os.makedirs(d, exist_ok=True)
        # resolve a box image (runner-owned writable rootfs) if the policy names one
        image_rootfs = None
        if policy.image:
            from ..image import resolve
            image_rootfs = resolve(policy.image).rootfs
        # let each storage provider set up its backing (mkdir, download, …) before start
        for m in policy.mounts:
            m.provider.prepare(self._cid)
        # The bundle gets the *merged* environment, so the container's own
        # first process is pointed at the proxy too — not only later execs.
        oci.build_bundle(policy, self._bundle, env=self._base_env,
                         image_rootfs=image_rootfs)

        run_flags = ["run", "-bundle", self._bundle]
        if restore_from:
            run_flags.append(f"-fs-restore-image-path={restore_from}")
        run_flags.append(self._cid)
        run_cmd = self._scope_prefix(policy) + self._run_globals(platform) + run_flags
        self._held = subprocess.Popen(run_cmd, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE, text=True)
        if not self._wait_running():
            err = self._drain_held_stderr()
            self.close()
            raise BackendError(f"box failed to start: {err or 'held process exited'}")
        # network passthrough boxes need DNS. In image mode `/etc` is the (writable) image,
        # so inject the HOST's current resolver (matches the shared netns — corporate/split/
        # WSL stub, whatever the host uses). Host-bind boxes already see the host's /etc.
        if policy.network != "none" and policy.image:
            self._inject_host_resolv_conf()

    def _inject_host_resolv_conf(self) -> None:
        try:
            with open("/etc/resolv.conf", "rb") as f:   # follows symlinks -> resolved content
                data = f.read()
        except OSError:
            log.warning("no host /etc/resolv.conf to inject; DNS may not work in the box")
            return
        # replace any symlink with a real file, then write the host's resolver
        self.exec(["/bin/sh", "-c", "rm -f /etc/resolv.conf && cat > /etc/resolv.conf"],
                  stdin=data)

    def _wait_running(self) -> bool:
        deadline = time.monotonic() + _START_TIMEOUT_S
        while time.monotonic() < deadline:
            if self._held and self._held.poll() is not None:
                return False
            r = subprocess.run(self._ctl_globals() + ["state", self._cid],
                               capture_output=True, text=True)
            if r.returncode == 0 and '"status": "running"' in r.stdout:
                return True
            time.sleep(0.1)
        return False

    def _drain_held_stderr(self) -> str:
        if self._held and self._held.stderr:
            try:
                return self._held.stderr.read().strip()[:500]
            except Exception:  # noqa: BLE001
                return ""
        return ""

    def alive(self) -> bool:
        return self._held is not None and self._held.poll() is None

    def exec(
        self,
        cmd: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        stdin: bytes | None = None,
        timeout: float | None = None,
    ) -> ExecResult:
        if self._cid is None:
            raise BackendError("backend is not open")
        if not self.alive():
            raise BackendError("box is not running (held process exited — OOM-killed?)")

        argv = self._ctl_globals() + ["exec"]
        if cwd:
            argv += ["-cwd", cwd]
        merged_env = dict(self._base_env)
        if env:
            merged_env.update(env)
        for k, v in merged_env.items():
            argv += ["-env", f"{k}={v}"]
        argv += [self._cid, *cmd]

        started = time.monotonic()
        try:
            r = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            out = e.stdout or b""
            return self._result(out, b"timeout", 124, started)
        return self._result(r.stdout, r.stderr, r.returncode, started)

    def attach_context(self) -> dict:
        """Argv prefix + container id for a LOCAL, interactive `runsc exec` (PTY
        passthrough). The capturing `exec()` above can't carry an interactive terminal —
        it buffers stdout and never connects stdin — so REPLs (python3, bash -i) die on
        immediate EOF. Instead the daemon hands these pieces to the same-host, same-user
        CLI, which runs `runsc exec` itself with the user's terminal wired straight
        through (gVisor passes the host TTY fd into the sandbox; verified). The CLI
        appends `-cwd`/`-env`, then `<cid> <cmd>`."""
        if self._cid is None or not self.alive():
            raise BackendError("box is not running; cannot attach")
        return {"argv": self._ctl_globals() + ["exec"], "cid": self._cid}

    def _result(self, out: bytes, err: bytes, code: int, started: float) -> ExecResult:
        limit = self._policy.max_output_bytes if self._policy else 10 * 1024 * 1024
        truncated = len(out) > limit
        if truncated:
            out = out[:limit]
        return ExecResult(
            stdout=out.decode("utf-8", "replace"),
            stderr=err.decode("utf-8", "replace"),
            exit_code=code,
            truncated=truncated,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    def fscheckpoint(self, dest: str, *, leave_running: bool = True) -> None:
        """Save the box's filesystem (the overlay) to `dest` (restore via runsc
        `-fs-restore-image-path`). Requires a disk-backed overlay (scratch='disk').
        `leave_running` (default True) keeps the box alive — without `-leave-running`
        gVisor STOPS the box after checkpointing (verified ~30 ms either way)."""
        if self._cid is None or not self.alive():
            raise BackendError("box is not running; cannot checkpoint")
        if self._policy and self._policy.scratch == "memory":
            raise BackendError(
                "cannot checkpoint a scratch='memory' box — its overlay is RAM-backed and "
                "not checkpointable. Recreate the box with scratch='disk'."
            )
        os.makedirs(dest, exist_ok=True)
        cmd = self._ctl_globals() + ["fscheckpoint", "--image-path", dest]
        if leave_running:
            cmd.append("--leave-running")
        cmd.append(self._cid)
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise BackendError(f"fscheckpoint failed: {r.stderr.strip()[-300:]}")

    def commit(self) -> None:
        """Persist provider-backed volumes (e.g. fsspec upload). Disk/memory are no-ops."""
        if self._policy and self._cid:
            for m in self._policy.mounts:
                m.provider.commit(self._cid)

    def close(self) -> None:
        if self._proxy is not None:
            # Before the box goes: a proxy outliving the only client it had is
            # a listening socket nobody owns.
            try:
                self._proxy.stop()
            except Exception:  # noqa: BLE001 — teardown must not mask the rest
                log.warning("egress proxy shutdown failed", exc_info=True)
            self._proxy = None
        if self._cid and self._state:
            ctl = self._ctl_globals()
            subprocess.run(ctl + ["kill", self._cid, "KILL"], capture_output=True)
            subprocess.run(ctl + ["delete", "--force", self._cid], capture_output=True)
        if self._policy and self._cid:
            for m in self._policy.mounts:
                try:
                    m.provider.cleanup(self._cid)
                except Exception:  # noqa: BLE001 — cleanup must not mask teardown
                    log.warning("storage cleanup failed for %s", m.target, exc_info=True)
        if self._held is not None:
            try:
                self._held.wait(timeout=10)
            except Exception:  # noqa: BLE001
                self._held.kill()
            self._held = None
        for d in (self._bundle, self._state):
            if d:
                shutil.rmtree(d, ignore_errors=True)
        self._bundle = self._state = self._cid = self._policy = None
