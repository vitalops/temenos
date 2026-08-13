# Changelog

All notable changes to **temenos** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] — 2026-08-13

### Added
- **Filtered egress (`network="filtered"`).** A per-box allowlist proxy: `--filtered
  --allow-host api.acme.com --allow-host '*.stripe.com'`. Default-deny, `host` or
  `host:port` entries, `*.` wildcards for subdomains, IP literals only when written
  exactly, and cloud-metadata addresses refused by name. Refusals come back as a `403`
  with a readable body, so a tool inside the box surfaces something a model can act on.
  Bytes are metered per host — egress is a billing surface as well as a security one.
- **`temenos.net`** — `HostAllowlist` and `EgressProxy`, usable on their own.

### Changed
- **`Policy.network` is now `"none" | "filtered" | "host"`** rather than a bool. Bools
  still work on the way in (`False`→`"none"`, `True`→`"host"`), and the value is a `str`
  subclass whose truthiness is unchanged — `if policy.network:` still means "has
  network", which a plain string would have silently inverted for `"none"`.
- `Policy.allow_hosts` is refused unless `network="filtered"`; an allowlist nothing
  consults reads like containment and is not. Narrowing out of `filtered` drops it.
- `restrict()` walks `host → filtered → none` and refuses any step back up.

### Honest limits
- **`filtered` is cooperative, not enforced.** The box is pointed at the proxy via
  `HTTPS_PROXY`; hostile code that ignores the variable reaches the network directly,
  because a `filtered` box still shares the host netns. Enforcement needs pasta + nft
  TPROXY (`plan.md` §13) and is not built. `EgressProxy.enforced` is `False` and says so.
  For adversarial or multi-tenant workloads, `network="none"` remains the answer.

## [0.3.0] — 2026-06-07

### Added
- **Smart working-directory landing.** `temenos exec`, `temenos shell`, and `temenos claude`
  now open in your current directory for a **project** box (the repo is mounted at its real
  host path, so the host CWD exists inside the box) and at `/` for a **global** box. Boxes
  carry a `default_cwd` so an agent's MCP `exec` calls land in the project dir too. Plumbed
  through the Python `Box`, the daemon REST `create`, and the daemon client.
- **`TERM` forwarding** into interactive sessions, so curses tools — `vim`, `less`, `top`,
  `clear` — render correctly (defaults to `xterm-256color` when the host hasn't set one).
- **A shell welcome banner** summarizing the box at a glance (name, id, network, image,
  scratch/checkpoint mode, working dir); respects `NO_COLOR`.

## [0.2.0] — 2026-06-07

First published release.

### Added
- **Interactive shells (PTY passthrough).** `temenos shell` is now a real interactive
  terminal (bash if the box has it, else sh), and `temenos exec` gained `-it`
  (`--interactive`/`--tty`) for one-off interactive runs — REPLs and full-screen TUIs like
  `python3`, `bash -i`, and `vim` work as they would locally. Previously every shell line
  ran as a fresh captured `exec` with stdin disconnected, so any interactive program hit
  immediate EOF and exited. The CLI now wires your terminal straight into the box over a
  PTY (the `docker exec -it` model), via a new `GET /v1/boxes/{id}/attach` daemon endpoint.
  Without a controlling terminal (piped/redirected stdin), `-it` falls back to direct fd
  passthrough, so `echo … | temenos exec -it box -- python3` still works.

### Changed
- The old line-marker (`__TEMENOS_CWD__`) shell REPL is gone, replaced by the PTY shell.

### Fixed
- **Test hygiene:** a session-scoped reaper plus graceful daemon teardown ensure gVisor
  sandboxes are torn down even when a run is interrupted, so `runsc` processes no longer
  orphan and accumulate across test runs.

## [0.1.0] — unreleased

Baseline (never published). The core temenos runtime: named, persistent gVisor boxes with
a Python-native `Policy`, a per-user daemon (REST control plane + per-box MCP data plane),
the project-aware CLI (`create`/`exec`/`ls`/`rm`/`audit`/`diff`/`serve`), `temenos claude`
(native tools banned, only `mcp__temenos__*` allowed), box images (mmdebstrap/download/
minimal/host-copy builders), storage volumes, filesystem checkpoint/restore, and
systemd-backed memory limits.

[0.3.0]: https://github.com/farizrahman4u/temenos/releases/tag/v0.3.0
[0.2.0]: https://github.com/farizrahman4u/temenos/releases/tag/v0.2.0
