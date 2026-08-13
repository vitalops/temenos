"""temenos CLI (Layer 3). Thin wrapper over the core API.

Two command families:
  - `image build|ls|rm` and `serve` — pure/daemon control (no project context).
  - the git-style **project commands** (`create`/`ls`/`exec`/`shell`/`rm`/`audit`/`diff`)
    — these discover `.temenos/` by walking up from CWD, resolve a bare box name
    (project-first, then global — D15), and drive the one per-user daemon via its client.

Stdlib argparse — no runtime deps — so the core CLI works without the `[cli]` extra
(the project commands need `[cli]` for httpx, imported lazily).
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys

from . import image
from .exceptions import TemenosError
from .policy import Policy


def _cmd_image_build(args: argparse.Namespace) -> int:
    opts: dict[str, object] = {}
    if args.builder == "mmdebstrap":
        # suite/mirror default to None so the builder auto-detects the host distro
        # (passing a mismatched suite vs the host mirror yields an empty rootfs)
        if args.suite:
            opts["suite"] = args.suite
        if args.variant:
            opts["variant"] = args.variant
        if args.mirror:
            opts["mirror"] = args.mirror
        if args.arch:
            opts["arch"] = args.arch
        if args.include:
            opts["include"] = tuple(p for p in args.include.split(",") if p)
    elif args.builder == "host-copy":
        opts["force"] = args.force_copy   # never copies silently — see --force-copy
    elif args.builder == "download":
        if not args.url:
            print("error: --from download requires --url <rootfs tarball>", file=sys.stderr)
            return 2
        opts["url"] = args.url
    img = image.build(args.name, builder=args.builder, **opts)
    print(f"built image {args.name!r} ({args.builder}) -> {img.rootfs}")
    return 0


def _cmd_image_ls(args: argparse.Namespace) -> int:
    names = image.list_images()
    if not names:
        print("(no images)")
    for n in names:
        print(n)
    return 0


def _cmd_image_rm(args: argparse.Namespace) -> int:
    if image.remove(args.name):
        print(f"removed image {args.name!r}")
        return 0
    print(f"no such image: {args.name!r}", file=sys.stderr)
    return 1


def _cmd_serve(args: argparse.Namespace) -> int:
    import json
    import secrets

    import uvicorn

    from .manager import BoxManager
    from .server.app import create_app
    from .server.client import daemon_home, info_path

    os.makedirs(daemon_home(), mode=0o700, exist_ok=True)
    token = secrets.token_urlsafe(32)
    url = f"http://127.0.0.1:{args.port}"
    with open(info_path(), "w") as f:
        json.dump({"url": url, "token": token, "pid": os.getpid()}, f)
    mgr = BoxManager()
    mgr.start_checkpoint_loop()                 # D17: periodic checkpoint of dirty boxes
    app = create_app(manager=mgr, token=token)
    print(f"temenos daemon on {url}")
    try:
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    finally:
        mgr.shutdown()                          # tear down every box
        try:
            os.remove(info_path())
        except OSError:
            pass
    return 0


# -- project commands (D15/D16) -------------------------------------------------------

def _warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


def _parse_volume(spec: str):
    """`HOST:TARGET[:ro|rw]` -> a Mount backed by a DiskVolume."""
    from .storage import DiskVolume, Mount
    parts = spec.split(":")
    if len(parts) == 2:
        host, target, mode = parts[0], parts[1], "rw"
    elif len(parts) == 3:
        host, target, mode = parts
    else:
        raise TemenosError(f"--volume must be HOST:TARGET[:ro|rw], got {spec!r}")
    return Mount(target=target, provider=DiskVolume(os.path.abspath(host)), mode=mode)


def _policy_from_args(args: argparse.Namespace, project) -> Policy:
    """Build a Policy from the box-creation flags, including the repo mount (D16)."""
    if args.scratch == "memory" and not args.force_memory:
        raise TemenosError("scratch=memory is RAM-bound and CANNOT be checkpointed; "
                           "pass --force-memory to confirm you want an ephemeral fs")
    if args.ephemeral_fs and args.no_autosave:
        raise TemenosError("--ephemeral-fs and --no-autosave are mutually exclusive")
    checkpoint = "off" if args.ephemeral_fs else "on-close" if args.no_autosave else "auto"

    read: list[str] = []
    write: list[str] = []
    mounts = [_parse_volume(v) for v in (args.volume or [])]

    # The repo (the dir holding .temenos) mounts at its real path so in-box execution sees
    # the same files the trusted agent edits (D16). Live-writable by default; --ephemeral
    # flips it read-only. The box's own state (.temenos/) is masked with a tmpfs so the box
    # can't scribble it.
    if project is not None:
        if args.ephemeral:
            read.append(project.root)
        else:
            write.append(project.root)
        from .storage import MemoryVolume, Mount
        mounts.append(Mount(target=project.temenos_dir, provider=MemoryVolume(), mode="rw"))

    kwargs: dict[str, object] = dict(
        read=tuple(read), write=tuple(write), mounts=tuple(mounts),
        network=_net_mode(args), allow_hosts=tuple(args.allow_host or ()),
        scratch=args.scratch, checkpoint=checkpoint,
    )
    if args.image:
        kwargs["image"] = args.image
    if args.memory is not None:
        kwargs["max_memory_mb"] = args.memory
    if args.cpu is not None:
        kwargs["max_cpu_seconds"] = args.cpu
    return Policy(**kwargs)


def _load_box_policy(data_dir: str) -> Policy:
    """The policy a box was created with (its data dir is self-describing — D16)."""
    cfg = os.path.join(data_dir, "config.json")
    if os.path.exists(cfg):
        with open(cfg) as f:
            return Policy.from_dict(json.load(f))
    return Policy()


def _resolve_scoped(name: str, *, glob: bool, must_exist: bool = True):
    """Resolve a box in an EXPLICIT scope: project-local by default, global with --global.
    No silent cross-scope fallthrough — local commands never touch global boxes and vice
    versa (that's the separation). All not-found errors start with "no such box"."""
    from .project import find_project, resolve_box
    if glob:
        r = resolve_box(name, prefer="global")
        if must_exist and not r.exists:
            raise TemenosError(f"no such box: {name!r} in global scope")
        return r
    if find_project() is None:
        raise TemenosError(f"no such box: {name!r} — not inside a temenos project (no "
                           f".temenos/); use --global to target a global box")
    r = resolve_box(name, prefer="project")
    if must_exist and not r.exists:
        hint = " (a global box of that name exists — try --global)" if r.shadows_global else ""
        raise TemenosError(f"no such box: {name!r} in this project{hint}")
    return r


def _ensure_running(client, data_dir: str, name: str) -> str:
    """Idempotently bring the box up in the daemon (restores from its checkpoint if any)."""
    return client.create_box(data_dir, _load_box_policy(data_dir).to_dict(), name=name)["id"]


def _box_cwd(scope: str) -> str:
    """Where a session should land inside the box. A PROJECT box mounts the repo at its real
    host path, so the host CWD exists in the box → use it (host dir == box dir). A GLOBAL box
    has no repo mount → start at / (root)."""
    return os.getcwd() if scope == "project" else "/"


def _cmd_create(args: argparse.Namespace) -> int:
    from .project import DEFAULT_BOX, ensure_project, resolve_box
    from .server.client import connect_or_spawn
    name = args.name or DEFAULT_BOX
    if args.glob:
        project = None
        r = resolve_box(name, prefer="global")
    else:
        project = ensure_project()
        if project.created:
            print(f"initialized project at {project.temenos_dir}")
        if project.in_home:
            _warn("creating a project box in your home dir — did you mean a global box "
                  "(--global)?")
        r = resolve_box(name, prefer="project")
        if r.shadows_global:
            _warn(f"project box {name!r} shadows a global box of the same name")
    policy = _policy_from_args(args, project)
    client = connect_or_spawn()
    info = client.create_box(r.data_dir, policy.to_dict(), name=name)
    print(f"box {name!r} [{r.scope}] id={info['id']} "
          f"(net={policy.network}, checkpoint={policy.checkpoint})")
    return 0


def _cmd_box_ls(args: argparse.Namespace) -> int:
    """List boxes on disk in the requested scope (project by default, --global for global,
    --all for both), annotated with running/stopped from the daemon."""
    from .manager import box_id
    from .project import MARKER, find_project, global_boxes_dir
    from .server.client import connect

    want_global = args.glob or args.all
    want_local = args.all or not args.glob
    bases: list[tuple[str, str]] = []
    if want_local:
        proj = find_project()
        if proj is not None:
            bases.append(("project", os.path.join(proj, MARKER)))
        elif not want_global:
            print("(not inside a temenos project — use --global to list global boxes)")
            return 0
    if want_global:
        bases.append(("global", global_boxes_dir()))

    client = connect()
    running = {b["id"] for b in client.list_boxes() if b.get("running")} if client else set()

    rows = []
    for scope, base in bases:
        if not os.path.isdir(base):
            continue
        for entry in sorted(os.listdir(base)):
            d = os.path.join(base, entry)
            if os.path.exists(os.path.join(d, "config.json")):
                bid = box_id(d)
                rows.append((scope, entry, "running" if bid in running else "stopped", bid))
    if not rows:
        print("(no boxes)")
        return 0
    for scope, name, state, bid in rows:
        mark = "*" if scope == "project" else " "
        print(f"{mark} {name:<20} {scope:<7} {state:<8} {bid}")
    return 0


# picks bash when the box has it, else falls back to a plain interactive sh
_SHELL_PICK = ("if command -v bash >/dev/null 2>&1; then exec bash -i; "
               "else exec /bin/sh -i; fi")


def _stdin_is_tty() -> bool:
    try:
        return os.isatty(sys.stdin.fileno())
    except (AttributeError, ValueError, OSError):   # stream without a real fd / closed
        return False


def _copy_winsize(src_fd: int, dst_fd: int) -> None:
    import fcntl
    import termios
    try:
        sz = fcntl.ioctl(src_fd, termios.TIOCGWINSZ, b"\0" * 8)
        fcntl.ioctl(dst_fd, termios.TIOCSWINSZ, sz)
    except OSError:
        pass


def _interactive_exec(ctx: dict, cmd: list[str], *, cwd: str | None = None,
                      env: dict[str, str] | None = None) -> int:
    """Run `cmd` in the box with the local terminal wired straight through, so REPLs and
    full-screen TUIs behave. Bypasses the daemon's capturing exec: we run `runsc exec`
    ourselves (same host/user as the daemon) against a freshly-allocated PTY whose slave is
    the box process's stdio, put the real terminal in raw mode, and pump bytes between the
    two — the docker `exec -it` model. The box-side PTY does echo/line-editing; the local
    terminal stays raw so there's no double echo. Returns the box process's exit code.

    With no controlling terminal (piped/redirected stdin), we just inherit fds directly —
    `python3 < script` / `echo … | temenos exec -it … python3` still work."""
    argv = list(ctx["argv"])
    if cwd:
        argv += ["-cwd", cwd]
    # Forward TERM (host env isn't inherited into the box) so curses tools — clear, vim,
    # less, top — work; default to a widely-supported value if the host hasn't set one.
    env = {"TERM": os.environ.get("TERM") or "xterm-256color", **(env or {})}
    for k, v in env.items():
        argv += ["-env", f"{k}={v}"]
    argv += [ctx["cid"], *cmd]

    if not _stdin_is_tty():
        return subprocess.run(argv).returncode
    stdin_fd, stdout_fd = sys.stdin.fileno(), sys.stdout.fileno()

    import pty
    import select
    import signal
    import termios
    import tty

    master, slave = pty.openpty()
    old = termios.tcgetattr(stdin_fd)
    proc = None
    prev_winch = signal.getsignal(signal.SIGWINCH)
    try:
        _copy_winsize(stdin_fd, master)
        signal.signal(signal.SIGWINCH, lambda *_: _copy_winsize(stdin_fd, master))
        tty.setraw(stdin_fd)
        proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                                close_fds=True)
        os.close(slave)
        while True:
            try:
                ready, _, _ = select.select([stdin_fd, master], [], [], 0.2)
            except (InterruptedError, OSError):
                if proc.poll() is not None:
                    break
                continue
            if stdin_fd in ready:
                data = os.read(stdin_fd, 65536)
                if data:
                    os.write(master, data)
            if master in ready:
                try:
                    data = os.read(master, 65536)
                except OSError:        # slave hung up — box process exited
                    break
                if not data:
                    break
                os.write(stdout_fd, data)
            elif proc.poll() is not None:
                break
        return proc.wait()
    finally:
        termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old)
        signal.signal(signal.SIGWINCH, prev_winch)
        os.close(master)
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()


def _cmd_exec(args: argparse.Namespace) -> int:
    from .server.client import connect_or_spawn
    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        raise TemenosError("nothing to run (usage: temenos exec <box> -- <cmd> [args...])")
    r = _resolve_scoped(args.name, glob=args.glob)
    client = connect_or_spawn()
    bid = _ensure_running(client, r.data_dir, args.name)
    cwd = args.cwd or _box_cwd(r.scope)        # project box → host cwd; global → /
    if args.tty:
        # interactive: wire the local terminal into the box (REPLs, TUIs). The capturing
        # path can't carry a PTY, so attach locally. --timeout doesn't apply here.
        return _interactive_exec(client.attach_context(bid), cmd, cwd=cwd)
    res = client.exec(bid, cmd, cwd=cwd, timeout=args.timeout)
    sys.stdout.write(res["stdout"])
    if res["stderr"]:
        sys.stderr.write(res["stderr"])
    return int(res["exit_code"])


def _shell_banner(name: str, bid: str, scope: str, pol: Policy, data_dir: str) -> str:
    """A welcome banner + at-a-glance box facts, framed in a (fittingly) box."""
    home = os.path.expanduser("~")
    shown_dir = "~" + data_dir[len(home):] if data_dir.startswith(home) else data_dir
    rows = [
        ("box", f"{name}  [{scope}]"),
        ("id", bid),
        ("network", {
            "host": "host · full host passthrough (no filtering)",
            "filtered": "filtered · " + (", ".join(pol.allow_hosts) or "nothing allowed")
                        + "  (cooperative — see docs/security.md)",
            "none": "none · isolated (no egress)",
        }[pol.network]),
        ("image", pol.image or "host /usr (read-only)"),
        ("scratch", f"{pol.scratch}  ·  checkpoint={pol.checkpoint}"),
        ("dir", shown_dir),
    ]
    title = "⬡ temenos · secure agent sandbox"
    body = [f" {k:<8} {v}" for k, v in rows]
    inner = min(62, max(len(title) + 1, *(len(b) for b in body)))

    def fit(s: str) -> str:
        return s if len(s) <= inner else s[: inner - 1] + "…"

    top = "╭─ " + title + " " + "─" * max(0, inner - len(title) - 1) + "╮"
    bottom = "╰" + "─" * (inner + 2) + "╯"
    lines = [top] + [f"│ {fit(b).ljust(inner)} │" for b in body] + [bottom]

    no_color = os.environ.get("NO_COLOR") is not None
    dim, bold, reset = ("", "", "") if no_color else ("\033[2m", "\033[1m", "\033[0m")
    out = [f"{bold}{lines[0]}{reset}"] + [f"{dim}{ln}{reset}" for ln in lines[1:]]
    out.append(f"{dim}  host is invisible beyond policy · Ctrl-D or `exit` to leave{reset}")
    return "\n".join(out)


def _cmd_shell(args: argparse.Namespace) -> int:
    """Open a true interactive shell in the box (PTY passthrough): bash if present, else
    sh. The box is persistent, so filesystem changes and cwd survive across the session and
    across reconnects. Run `python3`, `vim`, etc. just like a local shell."""
    from .server.client import connect_or_spawn
    r = _resolve_scoped(args.name, glob=args.glob)
    client = connect_or_spawn()
    bid = _ensure_running(client, r.data_dir, args.name)
    ctx = client.attach_context(bid)
    if not _stdin_is_tty():
        raise TemenosError("temenos shell needs an interactive terminal "
                           "(use `temenos exec <box> -- <cmd>` for non-interactive runs)")
    print(_shell_banner(args.name, bid, r.scope, _load_box_policy(r.data_dir), r.data_dir))
    return _interactive_exec(ctx, ["/bin/sh", "-c", _SHELL_PICK], cwd=_box_cwd(r.scope))


def _cmd_box_rm(args: argparse.Namespace) -> int:
    from .manager import box_id
    from .server.client import connect
    r = _resolve_scoped(args.name, glob=args.glob)
    client = connect()
    if client is not None:
        try:
            client.delete_box(box_id(r.data_dir))    # stop it if the daemon holds it
        except TemenosError:
            pass                                      # not loaded in the daemon — fine
    if not args.keep_data:
        shutil.rmtree(r.data_dir, ignore_errors=True)
    print(f"removed box {args.name!r}" + (" (kept data dir)" if args.keep_data else ""))
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    from .manager import box_id
    from .server.client import connect
    r = _resolve_scoped(args.name, glob=args.glob)
    client = connect()
    if client is None:
        raise TemenosError("no running daemon — the audit log lives in the live box")
    try:
        entries = client.audit(box_id(r.data_dir))
    except TemenosError:
        raise TemenosError(f"box {args.name!r} is not running (no audit log)")
    if not entries:
        print("(no audit entries)")
        return 0
    for e in entries:
        print(f"{e['timestamp']}  {e['kind']:<8} {e['decision']:<6} {e['details']}")
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    from .server.client import connect_or_spawn
    r = _resolve_scoped(args.name, glob=args.glob)
    client = connect_or_spawn()
    bid = _ensure_running(client, r.data_dir, args.name)
    files = client.writes(bid)
    if not files:
        print("(no files under the box's write paths)")
        return 0
    print(f"# files under {args.name!r}'s write paths "
          "(write-set manifest; a true diff-vs-original is post-v1):")
    for f in files:
        print(f)
    return 0


# Native host-touching tools Claude must NOT use — its sole execution path is the box's
# MCP tools. `--strict-mcp-config` also stops a stray .mcp.json re-adding a host server.
_BANNED_NATIVE = ("Bash,Read,Write,Edit,MultiEdit,NotebookEdit,Glob,Grep,"
                  "WebFetch,WebSearch,Task")
_ALLOWED_TEMENOS = ("mcp__temenos__exec,mcp__temenos__read,"
                    "mcp__temenos__write,mcp__temenos__list")


def _cmd_claude(args: argparse.Namespace) -> int:
    """Attach a Claude Code session to a box: Claude runs on the host (auth/model API keep
    working) but every host-touching native tool is banned — its only execution path is the
    box's MCP tools (plan §8e)."""
    from .project import DEFAULT_BOX, ensure_project, resolve_box
    from .server.client import connect_or_spawn, read_info
    name = args.box or DEFAULT_BOX
    if args.glob:
        project = None
        r = resolve_box(name, prefer="global")
    else:
        project = ensure_project()
        if project.created:
            print(f"initialized project at {project.temenos_dir}")
        r = resolve_box(name, prefer="project")
        if r.shadows_global:
            _warn(f"project box {name!r} shadows a global box of the same name")
    policy = _policy_from_args(args, project)
    client = connect_or_spawn()
    # Land the agent's MCP exec calls in the host CWD (it exists in the box via the repo
    # mount) for a project box; root for a global one.
    bid = client.create_box(r.data_dir, policy.to_dict(), name=name,
                            cwd=_box_cwd(r.scope))["id"]

    info = read_info() or {}
    cfg = {"mcpServers": {"temenos": {
        "type": "http",
        "url": f"{info.get('url')}/mcp/{bid}",
        "headers": {"Authorization": f"Bearer {info.get('token')}"}}}}
    cfg_path = os.path.join(r.data_dir, "mcp.json")     # box-local, gitignored
    with open(cfg_path, "w") as f:
        json.dump(cfg, f, indent=2)

    claude_args = list(args.claude_args)
    if claude_args and claude_args[0] == "--":
        claude_args = claude_args[1:]
    argv = ["claude", "--strict-mcp-config", "--mcp-config", cfg_path,
            "--disallowedTools", _BANNED_NATIVE, "--allowedTools", _ALLOWED_TEMENOS,
            *claude_args]

    if args.dry_run:
        print(f"box {name!r} [{r.scope}] id={bid}")
        print(f"mcp config: {cfg_path}")
        print(" ".join(shlex.quote(a) for a in argv))
        return 0
    if shutil.which("claude") is None:
        raise TemenosError("`claude` not found on PATH (install Claude Code, or use --dry-run)")
    os.execvp("claude", argv)        # replace this process so Claude owns the TTY
    return 0                          # unreachable


def _cmd_version(args: argparse.Namespace) -> int:
    from . import __version__
    print(f"temenos {__version__}")
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Quick capability check: gVisor + platform, mmdebstrap, systemd memory enforcement."""
    from .backends.gvisor import GVisorBackend
    ok = GVisorBackend.is_available()
    print(f"gVisor (runsc):     {'yes' if ok else 'NO'}")
    if ok:
        try:
            print(f"  platform:         {GVisorBackend().detect_platform()}")
        except Exception as e:  # noqa: BLE001
            print(f"  platform:         (probe failed: {e})")
    print(f"mmdebstrap:         {'yes' if shutil.which('mmdebstrap') else 'no (image builds limited)'}")
    have_systemd = shutil.which("systemd-run") is not None
    print(f"systemd-run:        {'yes' if have_systemd else 'no — resource limits UNENFORCED'}")
    return 0 if ok else 1


def _net_mode(args: argparse.Namespace) -> str:
    """`--net/--no-net/--filtered/--allow-host` → one of the three modes.

    Naming a host implies filtering. Someone who wrote `--allow-host` wants an
    allowlist, and the alternative reading — full passthrough, allowlist
    ignored — is the dangerous one to guess.
    """
    if getattr(args, "filtered", False) or getattr(args, "allow_host", None):
        return "filtered"
    return "host" if getattr(args, "net", True) else "none"


def _add_box_flags(p: argparse.ArgumentParser) -> None:
    """Box-creation flags shared by `create` (and forwarded by `temenos claude` later)."""
    p.add_argument("--image", default=None, help="boot from a built image (see `temenos image`)")
    p.add_argument("--filtered", action="store_true",
                   help="egress only to --allow-host entries, via a per-box proxy. "
                        "COOPERATIVE: honoured by well-behaved clients, ignored by "
                        "hostile code — use --no-net to contain that.")
    p.add_argument("--allow-host", action="append", metavar="HOST[:PORT]",
                   help="a host a --filtered box may reach; implies --filtered. "
                        "`*.acme.com` matches subdomains. Repeatable; nothing is "
                        "reachable until something is listed.")
    p.add_argument("--net", "--network", dest="net", default=True,
                   action=argparse.BooleanOptionalAction,
                   help="host network passthrough (ON by default; use --no-net to isolate)")
    p.add_argument("--scratch", choices=("disk", "memory"), default="disk",
                   help="root-overlay medium (disk=checkpointable default; memory=ephemeral)")
    p.add_argument("--force-memory", dest="force_memory", action="store_true",
                   help="confirm scratch=memory (ephemeral, not checkpointable)")
    p.add_argument("--ephemeral-fs", dest="ephemeral_fs", action="store_true",
                   help="never checkpoint — throwaway filesystem")
    p.add_argument("--no-autosave", dest="no_autosave", action="store_true",
                   help="checkpoint only on close (disable the background loop)")
    p.add_argument("--ephemeral", action="store_true",
                   help="mount the repo read-only (default is live-writable)")
    p.add_argument("--volume", action="append", metavar="HOST:TARGET[:ro|rw]",
                   help="extra host dir mounted into the box (repeatable)")
    p.add_argument("--memory", type=int, default=None, metavar="MB", help="memory cap (MB)")
    p.add_argument("--cpu", type=int, default=None, metavar="SECONDS", help="CPU-time cap")
    p.add_argument("--global", dest="glob", action="store_true",
                   help="create a global (non-project) box instead of a .temenos/ one")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="temenos", description="trusted-agent box runtime")
    sub = p.add_subparsers(dest="group", required=True)

    img = sub.add_parser("image", help="manage box base images")
    isub = img.add_subparsers(dest="action", required=True)

    b = isub.add_parser("build", help="build a base image")
    b.add_argument("name")
    b.add_argument("--from", dest="builder", default="mmdebstrap",
                   choices=sorted(image.BUILDERS), help="builder (default: mmdebstrap)")
    b.add_argument("--suite", default=None, help="mmdebstrap suite (default: host distro)")
    b.add_argument("--variant", default="apt", help="mmdebstrap variant (default: apt)")
    b.add_argument("--mirror", default=None, help="mmdebstrap mirror URL")
    b.add_argument("--arch", default=None, help="mmdebstrap architecture")
    b.add_argument("--include", default=None, help="mmdebstrap extra packages (comma-sep)")
    b.add_argument("--url", default=None, help="rootfs tarball URL (for --from download)")
    b.add_argument("--force-copy", dest="force_copy", action="store_true",
                   help="confirm a full host /usr copy (required for --from host-copy)")
    b.set_defaults(func=_cmd_image_build)

    ls = isub.add_parser("ls", help="list images")
    ls.set_defaults(func=_cmd_image_ls)

    rm = isub.add_parser("rm", help="remove an image")
    rm.add_argument("name")
    rm.set_defaults(func=_cmd_image_rm)

    srv = sub.add_parser("serve", help="run the temenos daemon (one per user)")
    srv.add_argument("--port", type=int, default=int(os.environ.get("TEMENOS_PORT", "8839")))
    srv.set_defaults(func=_cmd_serve)

    # -- project commands (git-style; discover .temenos/, resolve project-first) --------
    cr = sub.add_parser("create", help="create (or ensure) a box in this project")
    cr.add_argument("name", nargs="?", default=None, help="box name (default: 'default')")
    _add_box_flags(cr)
    cr.set_defaults(func=_cmd_create)

    def _scope(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--global", dest="glob", action="store_true",
                            help="target a global box instead of this project's")

    bls = sub.add_parser("ls", help="list boxes (this project's by default)")
    bls.add_argument("--global", dest="glob", action="store_true", help="list global boxes")
    bls.add_argument("--all", action="store_true", help="list both project and global boxes")
    bls.set_defaults(func=_cmd_box_ls)

    ex = sub.add_parser("exec", help="run a command in a box")
    ex.add_argument("name")
    _scope(ex)
    ex.add_argument("--cwd", default=None, help="working dir inside the box")
    ex.add_argument("--timeout", type=float, default=None, help="seconds before kill")
    ex.add_argument("-i", "--interactive", "-t", "--tty", dest="tty", action="store_true",
                    help="wire your terminal into the box (PTY) for REPLs/TUIs like "
                         "`python3`; put it BEFORE the box name")
    ex.add_argument("cmd", nargs=argparse.REMAINDER,
                    help="the command (after the box name; an optional `--` is stripped)")
    ex.set_defaults(func=_cmd_exec)

    sh = sub.add_parser("shell", help="open a minimal REPL in a box")
    sh.add_argument("name")
    _scope(sh)
    sh.set_defaults(func=_cmd_shell)

    brm = sub.add_parser("rm", help="stop and delete a box")
    brm.add_argument("name")
    _scope(brm)
    brm.add_argument("--keep-data", dest="keep_data", action="store_true",
                     help="stop the box but keep its data dir (checkpoint/overlay)")
    brm.set_defaults(func=_cmd_box_rm)

    au = sub.add_parser("audit", help="show a box's audit log")
    au.add_argument("name")
    _scope(au)
    au.set_defaults(func=_cmd_audit)

    df = sub.add_parser("diff", help="list files under a box's write paths")
    df.add_argument("name")
    _scope(df)
    df.set_defaults(func=_cmd_diff)

    cl = sub.add_parser("claude", help="attach a Claude Code session to a box (natives banned)")
    cl.add_argument("--box", default=None, help="box name (default: 'default')")
    cl.add_argument("--dry-run", dest="dry_run", action="store_true",
                    help="print the box id, MCP config path and claude command, then exit")
    _add_box_flags(cl)
    cl.add_argument("claude_args", nargs=argparse.REMAINDER,
                    help="args passed through to claude (after an optional `--`)")
    cl.set_defaults(func=_cmd_claude)

    doc = sub.add_parser("doctor", help="check gVisor/platform/limits capability")
    doc.set_defaults(func=_cmd_doctor)

    ver = sub.add_parser("version", help="print the temenos version")
    ver.set_defaults(func=_cmd_version)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except TemenosError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
