"""Running the proxy next to a synchronous backend.

The backend drives ``runsc`` with ``subprocess`` and knows nothing about
asyncio; the proxy is asyncio because it is a socket server and that is the
sane way to write one. So the proxy gets its own event loop on a daemon
thread, started and stopped by the box lifecycle.

A thread rather than a subprocess because the proxy is in-process state — the
allowlist it was built with and the meter it fills in — and a subprocess would
mean serialising both ways for no isolation benefit: it runs with exactly the
runner's privileges either way.
"""
from __future__ import annotations

import asyncio
import threading

from .allowlist import HostAllowlist
from .proxy import EgressProxy


class RunningProxy:
    """A started :class:`EgressProxy`, driven from a thread of its own."""

    def __init__(self, proxy: EgressProxy, loop: asyncio.AbstractEventLoop,
                 thread: threading.Thread) -> None:
        self._proxy = proxy
        self._loop = loop
        self._thread = thread

    @property
    def url(self) -> str:
        return self._proxy.url

    @property
    def meter(self):
        return self._proxy.meter

    @property
    def enforced(self) -> bool:
        return self._proxy.enforced

    def env(self) -> dict[str, str]:
        return self._proxy.env()

    def stop(self, timeout: float = 5.0) -> None:
        """Close the listener and stop the loop. Safe to call twice."""
        if not self._thread.is_alive():
            return
        stopping = asyncio.run_coroutine_threadsafe(self._proxy.stop(), self._loop)
        try:
            stopping.result(timeout=timeout)
        except Exception:  # noqa: BLE001 — teardown is best effort
            pass
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=timeout)


def start_proxy(
    allow_hosts: "tuple[str, ...] | list[str] | HostAllowlist" = (),
    *,
    box: str = "",
    host: str = "127.0.0.1",
) -> RunningProxy:
    """Start a per-box proxy and return a handle. Blocks until it is listening.

    Blocking matters: the caller's next move is to write the proxy's address
    into the box's environment, and an address that isn't bound yet is a box
    whose first request is refused by the operating system.
    """
    loop = asyncio.new_event_loop()
    proxy = EgressProxy(allow_hosts, host=host, box=box)
    ready = threading.Event()

    def run() -> None:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(proxy.start())
        ready.set()
        try:
            loop.run_forever()
        finally:
            loop.close()

    thread = threading.Thread(target=run, name=f"temenos-egress-{box or 'box'}",
                              daemon=True)
    thread.start()
    if not ready.wait(timeout=10.0):  # pragma: no cover - a loop that won't start
        raise RuntimeError("egress proxy failed to start")
    return RunningProxy(proxy, loop, thread)


__all__ = ["RunningProxy", "start_proxy"]
