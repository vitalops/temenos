"""Filtered egress — the allowlist and the proxy. Pure Python; runs anywhere.

The box-side of this (a real `runsc` box pointed at a real proxy) is in
`tests/test_backends/test_gvisor.py`; everything here needs no privileges and
no gVisor, because the proxy is an ordinary asyncio server and the allowlist
is a pure function.

Two things are worth stating up front, because they are what the tests are
*for*:

* **Default-deny.** An allowlist that is empty reaches nothing. Every "yes"
  traces to an entry somebody wrote.
* **Cooperative, not enforced.** The proxy refuses what it is asked to refuse;
  it cannot stop a process that declines to use it. That is a property of the
  namespace plumbing (plan §13), not of this code, and
  `test_the_proxy_says_it_is_not_enforcement` pins the honesty rather than the
  mechanism.
"""
from __future__ import annotations

import asyncio

import pytest

from temenos.net import EgressProxy, HostAllowlist

# -- the allowlist --------------------------------------------------------------------

def test_nothing_is_reachable_by_default():
    empty = HostAllowlist()
    assert not empty.check("example.com", 443)
    assert not empty.check("127.0.0.1", 80)


def test_an_exact_host_matches_any_port():
    allow = HostAllowlist(["api.acme.com"])
    assert allow.check("api.acme.com", 443)
    assert allow.check("api.acme.com", 8080)
    assert not allow.check("acme.com", 443)


def test_a_port_can_be_pinned():
    allow = HostAllowlist(["api.acme.com:443"])
    assert allow.check("api.acme.com", 443)
    assert not allow.check("api.acme.com", 8080)


def test_a_wildcard_matches_subdomains_but_not_the_apex():
    allow = HostAllowlist(["*.acme.com"])
    assert allow.check("api.acme.com", 443)
    assert allow.check("a.b.acme.com", 443)
    assert not allow.check("acme.com", 443)
    # …and not a host that merely ends with the same letters.
    assert not allow.check("evilacme.com", 443)
    assert not allow.check("acme.com.evil.example", 443)


def test_matching_ignores_case_and_a_trailing_dot():
    allow = HostAllowlist(["api.acme.com"])
    assert allow.check("API.ACME.COM", 443)
    assert allow.check("api.acme.com.", 443)


def test_an_ip_is_reachable_only_if_somebody_wrote_that_ip():
    """A wildcard is about names. Letting one resolve to an address would make
    `*.acme.com` a way to reach whatever a DNS answer says."""
    assert not HostAllowlist(["*.acme.com"]).check("93.184.216.34", 443)
    assert HostAllowlist(["93.184.216.34"]).check("93.184.216.34", 443)


def test_private_space_is_refused_with_a_reason():
    allow = HostAllowlist(["*.acme.com"])
    for address in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "::1"):
        verdict = allow.check(address, 80)
        assert not verdict and "private" in verdict.reason


def test_the_metadata_service_is_named_in_its_refusal():
    """The most valuable thing a box can ask for, so the log line should say
    what it was rather than "not in the allowlist"."""
    verdict = HostAllowlist([]).check("169.254.169.254", 80)
    assert not verdict and "metadata" in verdict.reason


def test_a_deployment_may_still_name_a_private_address():
    """An operator whose partner service is on the LAN knows what they are
    doing; what they cannot do is reach it by accident."""
    assert HostAllowlist(["10.0.0.5:5432"]).check("10.0.0.5", 5432)
    assert not HostAllowlist(["10.0.0.5:5432"]).check("10.0.0.6", 5432)


def test_ipv6_entries_take_brackets():
    assert HostAllowlist(["[2606:2800:220:1::]:443"]).check("2606:2800:220:1::", 443)
    with pytest.raises(ValueError):
        HostAllowlist(["[::1"])


def test_a_bad_port_is_refused_when_it_is_written():
    with pytest.raises(ValueError):
        HostAllowlist(["acme.com:https"])


# -- the proxy ------------------------------------------------------------------------

async def _origin(handler=None):
    """A one-connection HTTP server standing in for an allowed host."""

    async def serve(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        body = b"upstream"
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n" + body
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler or serve, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _request(proxy: EgressProxy, raw: bytes) -> bytes:
    host, port = proxy.address
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(raw)
    await writer.drain()
    answer = await asyncio.wait_for(reader.read(-1), timeout=5)
    writer.close()
    return answer


@pytest.mark.asyncio
async def test_an_allowed_host_is_forwarded():
    server, port = await _origin()
    async with EgressProxy([f"127.0.0.1:{port}"]) as proxy:
        answer = await _request(
            proxy,
            f"GET http://127.0.0.1:{port}/x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode(),
        )
    server.close()
    assert b"200 OK" in answer and b"upstream" in answer


@pytest.mark.asyncio
async def test_a_refused_host_gets_a_readable_403():
    """The body matters: a tool in the box surfaces this to a model, and
    "not in the allowlist" is something a model can act on. A connection
    reset is not."""
    async with EgressProxy(["api.acme.com"]) as proxy:
        answer = await _request(
            proxy, b"GET http://evil.example/x HTTP/1.1\r\nHost: evil.example\r\n\r\n"
        )
    assert b"403" in answer
    assert b"egress refused" in answer and b"evil.example" in answer


@pytest.mark.asyncio
async def test_connect_to_an_allowed_host_tunnels():
    server, port = await _origin()
    async with EgressProxy([f"127.0.0.1:{port}"]) as proxy:
        host, pport = proxy.address
        reader, writer = await asyncio.open_connection(host, pport)
        writer.write(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode())
        await writer.drain()
        established = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        assert b"200" in established

        # The tunnel is transparent: what goes in comes out at the origin.
        writer.write(b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        body = await asyncio.wait_for(reader.read(-1), timeout=5)
        writer.close()
    server.close()
    assert b"upstream" in body


@pytest.mark.asyncio
async def test_connect_to_a_refused_host_never_opens_a_socket():
    async with EgressProxy(["api.acme.com"]) as proxy:
        answer = await _request(proxy, b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
    assert b"403" in answer and b"not in the allowlist" in answer


@pytest.mark.asyncio
async def test_the_metadata_address_is_refused_through_the_proxy():
    async with EgressProxy(["*.acme.com"]) as proxy:
        answer = await _request(proxy, b"CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n")
    assert b"403" in answer and b"metadata" in answer


@pytest.mark.asyncio
async def test_an_origin_form_request_is_refused_with_advice():
    """Somebody pointed a plain HTTP client at the proxy port. Say so."""
    async with EgressProxy(["api.acme.com"]) as proxy:
        answer = await _request(proxy, b"GET /x HTTP/1.1\r\nHost: api.acme.com\r\n\r\n")
    assert b"400" in answer and b"absolute URI" in answer


@pytest.mark.asyncio
async def test_garbage_is_refused_rather_than_crashing_the_proxy():
    async with EgressProxy(["api.acme.com"]) as proxy:
        assert b"400" in await _request(proxy, b"\x16\x03\x01 not http\r\n\r\n")
        # …and the proxy is still serving afterwards.
        answer = await _request(proxy, b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
    assert b"403" in answer


@pytest.mark.asyncio
async def test_bytes_are_metered_per_host():
    """Egress is a billing surface as well as a security one, and a proxy
    everything already passes through is the only place to count it once."""
    server, port = await _origin()
    async with EgressProxy([f"127.0.0.1:{port}"]) as proxy:
        await _request(
            proxy,
            f"GET http://127.0.0.1:{port}/x HTTP/1.1\r\nHost: h\r\n\r\n".encode(),
        )
        assert proxy.meter.allowed == 1
        assert proxy.meter.received > 0
        assert proxy.meter.by_host["127.0.0.1"] > 0
    server.close()


@pytest.mark.asyncio
async def test_refusals_are_counted_too():
    async with EgressProxy(["api.acme.com"]) as proxy:
        await _request(proxy, b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
        assert proxy.meter.refused == 1 and proxy.meter.allowed == 0


@pytest.mark.asyncio
async def test_the_environment_points_a_box_at_the_proxy():
    async with EgressProxy(["api.acme.com"]) as proxy:
        env = proxy.env()
        # Both cases, because the convention is ancient and split.
        assert env["HTTPS_PROXY"] == env["https_proxy"] == proxy.url
    # And the address survives teardown, so a log line written afterwards
    # names the port this proxy had rather than 0.
    assert proxy.url == env["HTTPS_PROXY"]


@pytest.mark.asyncio
async def test_loopback_is_not_exempted_from_the_proxy():
    """A filtered box shares the host's network namespace, so `127.0.0.1`
    inside it is the *host*. The obvious `NO_PROXY=localhost` would hand every
    box a direct line to whatever the host runs locally — which is the most
    valuable thing on the far side of this control."""
    async with EgressProxy(["api.acme.com"]) as proxy:
        env = proxy.env()
    assert "NO_PROXY" not in env and "no_proxy" not in env


@pytest.mark.asyncio
async def test_a_loopback_service_is_refused_like_anything_else():
    async with EgressProxy(["api.acme.com"]) as proxy:
        answer = await _request(proxy, b"CONNECT 127.0.0.1:5432 HTTP/1.1\r\n\r\n")
    assert b"403" in answer and b"private or link-local" in answer


@pytest.mark.asyncio
async def test_the_proxy_says_it_is_not_enforcement():
    """The honesty this whole feature depends on. A caller that believes
    `filtered` contains hostile code has been misled, and the property that
    says otherwise should be impossible to miss."""
    async with EgressProxy(["api.acme.com"]) as proxy:
        assert proxy.enforced is False
