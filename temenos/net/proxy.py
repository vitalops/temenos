"""The per-box egress proxy — default-deny, and it meters what it passes.

`plan.md` §13 specifies filtered egress as *pasta + in-namespace nft TPROXY →
SNI/Host allowlist proxy + stub DNS*. This is the allowlist proxy half, and it
is the half that is pure Python and therefore testable everywhere. The
namespace plumbing that makes it **inescapable** is the other half and is not
built — see :attr:`EgressProxy.enforced` and `docs/security.md`.

What it speaks: ordinary HTTP proxy protocol, because that is what every
client in a box already knows how to use from ``HTTPS_PROXY``.

* ``CONNECT host:port`` — the TLS case. The allowlist is checked against the
  name **the client asked for**, then bytes are tunnelled without being
  inspected. There is no interception and no certificate to trust: the box
  gets end-to-end TLS to a host somebody allowed.
* ``GET http://host/path`` — the plain-HTTP case, forwarded as-is.

Everything else, and anything not on the list, gets ``403`` and a body that
says which entry was missing — an agent reading its own error should be able
to tell "I am not allowed there" from "the network is broken".

Bytes are counted per host on the way through. The roadmap treats egress as a
billing surface as well as a security one, and a proxy that everything already
goes through is the only place that can count it once.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field

from .allowlist import HostAllowlist

log = logging.getLogger("temenos.net")

#: Give up on a connection that never becomes a request. A box that opens
#: sockets and says nothing is a box holding the proxy's file descriptors.
HEADER_TIMEOUT = 15.0

#: A request line plus headers larger than this is not a request we want.
MAX_HEADER_BYTES = 64 * 1024

#: How long to wait connecting to an allowed host before giving up.
CONNECT_TIMEOUT = 20.0

_REQUEST = re.compile(rb"^([A-Z]+) (\S+) (HTTP/1\.[01])\r?\n")


@dataclass
class Meter:
    """Bytes and decisions, per host. Cheap enough to keep always."""

    allowed: int = 0
    refused: int = 0
    sent: int = 0
    received: int = 0
    by_host: dict[str, int] = field(default_factory=dict)

    def record(self, host: str, *, sent: int = 0, received: int = 0) -> None:
        self.sent += sent
        self.received += received
        self.by_host[host] = self.by_host.get(host, 0) + sent + received


class EgressProxy:
    """An HTTP proxy that only reaches what a policy named.

    One per box, bound to loopback on an ephemeral port. Loopback because the
    box shares the host's network namespace in this mode — the address has to
    be reachable from inside the box and from nowhere else.
    """

    def __init__(
        self,
        allowlist: "HostAllowlist | tuple[str, ...] | list[str]" = (),
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        box: str = "",
    ) -> None:
        self.allowlist = (
            allowlist if isinstance(allowlist, HostAllowlist) else HostAllowlist(allowlist)
        )
        self._host = host
        self._port = port
        self.box = box
        self.meter = Meter()
        self._server: asyncio.AbstractServer | None = None
        #: Remembered once bound, so a log line or an error written after
        #: teardown names the port this proxy actually had rather than 0.
        self._bound: tuple[str, int] | None = None

    # -- what a caller may believe ----------------------------------------------------

    @property
    def enforced(self) -> bool:
        """Whether a box *cannot* bypass this proxy.

        ``False``, today, and the honesty here is the point: the box is
        pointed at the proxy with ``HTTPS_PROXY``, which every well-behaved
        client honours and a hostile process ignores. Making it ``True`` needs
        the box in its own network namespace with the proxy as the only route
        out — `plan.md` §13's pasta + nft TPROXY — which is not built.

        So: filtered egress is a real control against an agent's *tools* and a
        real accident-preventer against ``pip install`` reaching the wrong
        index. It is not a containment boundary for hostile code. That case is
        still ``network='none'``.
        """
        return False

    @property
    def url(self) -> str:
        return f"http://{self.address[0]}:{self.address[1]}"

    @property
    def address(self) -> tuple[str, int]:
        if self._server is not None and self._server.sockets:
            sock = self._server.sockets[0].getsockname()
            self._bound = (sock[0], sock[1])
        return self._bound or (self._host, self._port)

    def env(self) -> dict[str, str]:
        """The environment that points a box at this proxy.

        Both cases of every variable, because the convention is ancient and
        split and a client that reads only ``http_proxy`` is not unusual.

        **No ``NO_PROXY``, deliberately.** The obvious entry to put there is
        loopback — "so a box talking to itself doesn't loop through the
        proxy" — and it is exactly wrong here: a filtered box shares the
        host's network namespace, so ``127.0.0.1`` inside it *is the host*.
        Exempting loopback would hand every box a direct line to whatever the
        host runs locally, which is the most valuable thing on the far side of
        this control. A box that genuinely needs a loopback service names it
        in ``allow_hosts`` like any other destination.

        (The proxy's own address needs no exemption: a client connects to its
        proxy directly by definition.)
        """
        url = self.url
        return {
            "HTTP_PROXY": url, "http_proxy": url,
            "HTTPS_PROXY": url, "https_proxy": url,
            "ALL_PROXY": url, "all_proxy": url,
        }

    # -- lifecycle --------------------------------------------------------------------

    async def start(self) -> "EgressProxy":
        self._server = await asyncio.start_server(
            self._serve, self._host, self._port, reuse_address=True
        )
        log.info("box %s: egress proxy on %s, %d allowed entr%s", self.box or "?",
                 self.url, len(self.allowlist.entries),
                 "y" if len(self.allowlist.entries) == 1 else "ies")
        return self

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> "EgressProxy":
        return await self.start()

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()

    # -- serving ----------------------------------------------------------------------

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=HEADER_TIMEOUT
            )
        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            return await _close(writer)
        except asyncio.LimitOverrunError:
            return await _refuse(writer, 431, "request headers too large")

        if len(head) > MAX_HEADER_BYTES:
            return await _refuse(writer, 431, "request headers too large")

        match = _REQUEST.match(head)
        if match is None:
            return await _refuse(writer, 400, "not an HTTP request")

        method, target = match.group(1).decode(), match.group(2).decode()
        try:
            if method == "CONNECT":
                await self._connect(target, head, reader, writer)
            else:
                await self._forward(method, target, head, reader, writer)
        except ConnectionError:
            await _close(writer)

    async def _connect(self, target: str, head: bytes, reader, writer) -> None:
        """``CONNECT host:port`` — check the name, then get out of the way."""
        host, _, port_text = target.rpartition(":")
        host = host.strip("[]")
        try:
            port = int(port_text)
        except ValueError:
            return await _refuse(writer, 400, f"bad CONNECT target {target!r}")

        verdict = self.allowlist.check(host, port)
        if not verdict:
            self.meter.refused += 1
            log.warning("box %s: egress refused %s:%s — %s", self.box or "?", host,
                        port, verdict.reason)
            return await _refuse(writer, 403, f"egress refused: {verdict.reason}")

        try:
            upstream_r, upstream_w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
            )
        except (OSError, TimeoutError) as exc:
            return await _refuse(writer, 502, f"cannot reach {host}:{port}: {exc}")

        self.meter.allowed += 1
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        await self._pipe(host, reader, writer, upstream_r, upstream_w)

    async def _forward(self, method: str, target: str, head: bytes, reader, writer) -> None:
        """Plain HTTP, which arrives with an absolute URI in the request line."""
        if not target.lower().startswith(("http://", "https://")):
            return await _refuse(
                writer, 400,
                "this is a proxy: send an absolute URI or CONNECT, not an origin-form path",
            )
        rest = target.split("://", 1)[1]
        authority = rest.split("/", 1)[0]
        path = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
        host, _, port_text = authority.rpartition(":")
        if not host:
            host, port = authority, 80
        else:
            host = host.strip("[]")
            try:
                port = int(port_text)
            except ValueError:
                host, port = authority, 80

        verdict = self.allowlist.check(host, port)
        if not verdict:
            self.meter.refused += 1
            log.warning("box %s: egress refused %s — %s", self.box or "?", target,
                        verdict.reason)
            return await _refuse(writer, 403, f"egress refused: {verdict.reason}")

        try:
            upstream_r, upstream_w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
            )
        except (OSError, TimeoutError) as exc:
            return await _refuse(writer, 502, f"cannot reach {host}:{port}: {exc}")

        self.meter.allowed += 1
        # Rewrite the absolute URI to origin form; everything else is passed
        # through untouched, including the client's own headers.
        first, _, tail = head.partition(b"\r\n")
        rewritten = f"{method} {path} HTTP/1.1".encode() + b"\r\n" + tail
        upstream_w.write(rewritten)
        await upstream_w.drain()
        await self._pipe(host, reader, writer, upstream_r, upstream_w)

    async def _pipe(self, host: str, client_r, client_w, upstream_r, upstream_w) -> None:
        """Shovel bytes both ways until either end is done, counting them."""

        async def one_way(src, dst, *, outbound: bool) -> None:
            try:
                while chunk := await src.read(65536):
                    dst.write(chunk)
                    await dst.drain()
                    self.meter.record(
                        host,
                        **({"sent": len(chunk)} if outbound else {"received": len(chunk)}),
                    )
            except (ConnectionError, asyncio.IncompleteReadError):
                pass
            finally:
                with_suppressed(dst.close)

        await asyncio.gather(
            one_way(client_r, upstream_w, outbound=True),
            one_way(upstream_r, client_w, outbound=False),
        )
        await _close(client_w)


def with_suppressed(fn) -> None:
    try:
        fn()
    except Exception:  # pragma: no cover - closing a closed transport
        pass


async def _refuse(writer: asyncio.StreamWriter, status: int, message: str) -> None:
    """Answer with a status and a body an agent can read.

    The body matters: a tool inside the box surfaces this text to a model, and
    "egress refused: api.evil.example:443 is not in the allowlist" is a thing
    a model can act on. A bare connection reset is not.
    """
    reason = {400: "Bad Request", 403: "Forbidden", 431: "Request Header Fields Too Large",
              502: "Bad Gateway"}.get(status, "Error")
    body = message.encode()
    writer.write(
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n".encode() + body
    )
    try:
        await writer.drain()
    except ConnectionError:  # pragma: no cover - the client already left
        pass
    await _close(writer)


async def _close(writer: asyncio.StreamWriter) -> None:
    with_suppressed(writer.close)
    try:
        await writer.wait_closed()
    except (ConnectionError, RuntimeError):  # pragma: no cover
        pass


__all__ = ["CONNECT_TIMEOUT", "HEADER_TIMEOUT", "EgressProxy", "Meter"]
