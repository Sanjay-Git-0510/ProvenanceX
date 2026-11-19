"""Egress proxy: allowlist, SSRF and DNS-rebinding protections, limits. In-process, offline:
the resolver is injected and "upstream" servers listen on 127.0.0.1. Only the positive-path
tests replace the address check (127.0.0.1 is, correctly, not public); every SSRF test uses
the real check. tests/integration/test_egress_proxy_live.py runs the real container."""

import asyncio
import contextlib

import pytest

from app.egress_proxy.policy import Denied, Policy, is_public_address, normalize_host
from app.egress_proxy.server import EgressProxy, ProxyConfig

ALLOWED = ["github.com", "huggingface.co", "us.aws.cdn.hf.co"]


# --------------------------------------------------------------------------- policy
@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.5",
        "172.16.3.4",
        "192.168.1.1",
        "127.0.0.1",
        "127.8.8.8",
        "0.0.0.0",  # noqa: S104 - an address under test, not a bind
        "169.254.169.254",  # cloud metadata
        "169.254.0.1",
        "100.64.0.1",
        "192.0.0.170",
        "198.18.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "240.0.0.1",
        "192.0.2.10",
        "::1",
        "::",
        "fe80::1",
        "fd00::1",
        "fc00::1",
        "ff02::1",
        "fd00:ec2::254",  # AWS metadata over IPv6
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",  # IPv4-mapped
        "64:ff9b::a9fe:a9fe",  # NAT64 of 169.254.169.254
        "2002:7f00:1::1",  # 6to4 of 127.0.0.1
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
        "not-an-ip",
        "",
    ],
)
def test_non_public_addresses_are_refused(address):
    assert not is_public_address(address)


@pytest.mark.parametrize("address", ["140.82.112.3", "18.164.52.75", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(address):
    assert is_public_address(address)


@pytest.mark.parametrize(
    ("host", "port"),
    [
        ("evil.example.com", 443),
        ("api.github.com", 443),  # subdomains are NOT implied (no wildcards)
        ("github.com.evil.com", 443),
        ("evilgithub.com", 443),
        ("github.com", 80),
        ("github.com", 22),
        ("github.com", 8443),
        ("github.com.", 443),
        ("140.82.112.3", 443),
        ("[::1]", 443),
        ("127.0.0.1", 443),
        ("user@github.com", 443),
        ("", 443),
        ("localhost", 443),
        ("postgres", 443),  # an internal Compose service name
        ("egress-proxy", 3128),
        ("metadata.google.internal", 443),
    ],
)
def test_targets_off_the_allowlist_are_refused(host, port):
    with pytest.raises(Denied):
        Policy.from_lists(ALLOWED).check_target(host, port)


def test_allowlisted_targets_pass_case_insensitively():
    policy = Policy.from_lists(ALLOWED)
    assert policy.check_target("GitHub.com", 443) == "github.com"
    assert policy.check_target("us.aws.cdn.hf.co", 443) == "us.aws.cdn.hf.co"


def test_wildcards_cannot_be_configured():
    with pytest.raises(Denied):
        Policy.from_lists(["*.hf.co"])
    with pytest.raises(ValueError):
        Policy.from_lists([])


def test_mixed_public_and_private_answers_are_refused():
    with pytest.raises(Denied):
        Policy.check_addresses(["140.82.112.3", "10.0.0.5"])
    with pytest.raises(Denied):
        Policy.check_addresses([])
    assert Policy.check_addresses(["140.82.112.3", "140.82.112.3"]) == ["140.82.112.3"]


def test_normalize_host_rejects_malformed_names():
    for bad in ["-a.com", "a..com", "a" * 64 + ".com", "a_b.com", "x"]:
        with pytest.raises(Denied):
            normalize_host(bad)


# --------------------------------------------------------------------------- server
class Upstream:
    """A local TCP server standing in for github.com: echoes, floods or stays silent."""

    def __init__(self, mode: str = "echo", flood_bytes: int = 0) -> None:
        self.mode = mode
        self.flood_bytes = flood_bytes
        self.received = bytearray()
        self.connections = 0
        self.server: asyncio.base_events.Server | None = None

    async def handle(self, reader, writer):
        self.connections += 1
        try:
            if self.mode == "flood":
                chunk = b"x" * 65536
                sent = 0
                while sent < self.flood_bytes:
                    writer.write(chunk)
                    await writer.drain()
                    sent += len(chunk)
            elif self.mode == "silent":
                await asyncio.sleep(30)
            else:
                while data := await reader.read(65536):
                    self.received += data
                    writer.write(data)
                    await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def start(self) -> int:
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]


def _loopback_only(addresses):
    # Positive-path tests only: treat the local upstream as the "public" destination.
    if addresses != ["127.0.0.1"]:
        raise Denied("unexpected address in test")
    return addresses


async def _proxy(upstream_port: int | None = None, *, real_check=False, resolver=None, **cfg):
    calls = []

    async def resolve(host, port):
        calls.append((host, port))
        return ["127.0.0.1"]

    policy = Policy(frozenset(ALLOWED), frozenset({upstream_port or 443}))
    config = ProxyConfig(
        policy=policy,
        host="127.0.0.1",
        port=0,
        resolver=resolver or resolve,
        **({} if real_check else {"address_check": _loopback_only}),
        **cfg,
    )
    proxy = EgressProxy(config)
    await proxy.start()
    return proxy, calls


async def _request(port: int, head: bytes, then: bytes = b"", read_until_close=True):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(head)
    await writer.drain()
    status = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
    body = b""
    if then:
        writer.write(then)
        await writer.drain()
    if read_until_close:
        with contextlib.suppress(asyncio.IncompleteReadError, ConnectionError):
            body = await asyncio.wait_for(reader.read(-1), timeout=10)
    writer.close()
    return status, body


def run(coro):
    return asyncio.run(coro)


def test_allowed_connect_is_tunneled_to_the_validated_address():
    async def scenario():
        upstream = Upstream()
        up_port = await upstream.start()
        proxy, calls = await _proxy(up_port)
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.bound_port)
        writer.write(
            f"CONNECT github.com:{up_port} HTTP/1.1\r\nHost: github.com\r\n"
            "Proxy-Authorization: Basic c2VjcmV0\r\n\r\n".encode()
        )
        status = await reader.readuntil(b"\r\n\r\n")
        writer.write(b"tls-bytes")
        await writer.drain()
        echoed = await asyncio.wait_for(reader.readexactly(9), timeout=5)
        writer.close()
        proxy.server.close()
        upstream.server.close()
        return status, echoed, calls, bytes(upstream.received)

    status, echoed, calls, received = run(scenario())
    assert status.startswith(b"HTTP/1.1 200")
    assert echoed == b"tls-bytes"
    assert len(calls) == 1  # resolved exactly once
    # Nothing from the client's request head (credentials included) reaches upstream.
    assert received == b"tls-bytes"


@pytest.mark.parametrize(
    "head",
    [
        b"GET http://github.com/ HTTP/1.1\r\nHost: github.com\r\n\r\n",
        b"POST http://github.com/ HTTP/1.1\r\n\r\n",
    ],
)
def test_plain_http_proxying_is_refused(head):
    async def scenario():
        proxy, calls = await _proxy()
        out = await _request(proxy.bound_port, head)
        proxy.server.close()
        return out, calls

    (status, _), calls = run(scenario())
    assert status.startswith(b"HTTP/1.1 405")
    assert calls == []


@pytest.mark.parametrize(
    "target",
    [
        "evil.example.com:443",
        "github.com:80",
        "127.0.0.1:443",
        "[::1]:443",
        "169.254.169.254:443",
        "postgres:5432",
        "api:8000",
        "hardhat:8545",
        "github.com",
    ],
)
def test_disallowed_targets_get_403_without_any_dns_lookup(target):
    async def scenario():
        proxy, calls = await _proxy()
        out = await _request(proxy.bound_port, f"CONNECT {target} HTTP/1.1\r\n\r\n".encode())
        proxy.server.close()
        return out, calls

    (status, _), calls = run(scenario())
    assert status.startswith((b"HTTP/1.1 403", b"HTTP/1.1 400"))
    assert calls == []


@pytest.mark.parametrize(
    "answer",
    [
        ["127.0.0.1"],
        ["10.1.2.3"],
        ["169.254.169.254"],
        ["::ffff:127.0.0.1"],
        ["140.82.112.3", "192.168.0.10"],  # one bad answer poisons the lookup
        [],
    ],
)
def test_names_resolving_to_internal_addresses_are_refused(answer):
    """The real address check: an allowlisted name pointing inside is never connected."""

    async def scenario():
        async def resolve(host, port):
            return answer

        proxy, _ = await _proxy(real_check=True, resolver=resolve)
        out = await _request(proxy.bound_port, b"CONNECT github.com:443 HTTP/1.1\r\n\r\n")
        proxy.server.close()
        return out

    status, _ = run(scenario())
    assert status.startswith(b"HTTP/1.1 403")


def test_dns_rebinding_cannot_swap_the_address_after_validation():
    """The name is resolved once; the validated answer is the one connected to."""

    async def scenario():
        upstream = Upstream()
        up_port = await upstream.start()
        answers = [["127.0.0.1"], ["10.9.9.9"]]
        seen = []

        async def rebinding(host, port):
            seen.append(host)
            return answers[min(len(seen) - 1, 1)]

        proxy, _ = await _proxy(up_port, resolver=rebinding)
        status, _ = await _request(
            proxy.bound_port,
            f"CONNECT github.com:{up_port} HTTP/1.1\r\n\r\n".encode(),
            then=b"x",
            read_until_close=False,
        )
        await asyncio.sleep(0.1)
        proxy.server.close()
        upstream.server.close()
        return status, seen, upstream.connections

    status, seen, connections = run(scenario())
    assert status.startswith(b"HTTP/1.1 200")
    assert seen == ["github.com"] and connections == 1


def test_resolver_failure_is_refused():
    async def scenario():
        async def broken(host, port):
            raise OSError("no such host")

        proxy, _ = await _proxy(real_check=True, resolver=broken)
        out = await _request(proxy.bound_port, b"CONNECT github.com:443 HTTP/1.1\r\n\r\n")
        proxy.server.close()
        return out

    status, _ = run(scenario())
    assert status.startswith(b"HTTP/1.1 403")


def test_oversized_download_is_cut_at_the_byte_cap():
    async def scenario():
        upstream = Upstream("flood", flood_bytes=8 * 1024 * 1024)
        up_port = await upstream.start()
        proxy, _ = await _proxy(up_port, max_down_bytes=1024 * 1024)
        status, body = await _request(
            proxy.bound_port, f"CONNECT github.com:{up_port} HTTP/1.1\r\n\r\n".encode()
        )
        proxy.server.close()
        upstream.server.close()
        return status, len(body)

    status, received = run(scenario())
    assert status.startswith(b"HTTP/1.1 200")
    assert received <= 1024 * 1024 + 65536  # cut within one chunk of the cap
    assert received < 8 * 1024 * 1024


def test_idle_tunnel_is_closed():
    async def scenario():
        upstream = Upstream("silent")
        up_port = await upstream.start()
        proxy, _ = await _proxy(up_port, idle_timeout=0.5)
        loop = asyncio.get_running_loop()
        start = loop.time()
        status, _ = await _request(
            proxy.bound_port, f"CONNECT github.com:{up_port} HTTP/1.1\r\n\r\n".encode()
        )
        took = loop.time() - start
        proxy.server.close()
        upstream.server.close()
        return status, took

    status, took = run(scenario())
    assert status.startswith(b"HTTP/1.1 200")
    assert took < 5


def test_tunnel_has_a_maximum_duration():
    async def scenario():
        upstream = Upstream()
        up_port = await upstream.start()
        proxy, _ = await _proxy(up_port, max_tunnel_seconds=0.5, idle_timeout=30)
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.bound_port)
        writer.write(f"CONNECT github.com:{up_port} HTTP/1.1\r\n\r\n".encode())
        await reader.readuntil(b"\r\n\r\n")
        loop = asyncio.get_running_loop()
        start = loop.time()
        with contextlib.suppress(ConnectionError, OSError):
            for _ in range(100):  # keep the tunnel busy so only the duration limit can end it
                writer.write(b"ping")
                await writer.drain()
                if not await asyncio.wait_for(reader.read(4), timeout=5):
                    break
                await asyncio.sleep(0.05)
        took = loop.time() - start
        writer.close()
        proxy.server.close()
        upstream.server.close()
        return took

    assert run(scenario()) < 4


def test_client_that_sends_nothing_times_out():
    async def scenario():
        proxy, _ = await _proxy(header_timeout=0.5)
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.bound_port)
        data = await asyncio.wait_for(reader.read(-1), timeout=5)
        writer.close()
        proxy.server.close()
        return data

    assert run(scenario()).startswith(b"HTTP/1.1 408")


def test_oversized_request_head_is_refused():
    async def scenario():
        proxy, calls = await _proxy()
        head = b"CONNECT github.com:443 HTTP/1.1\r\n" + b"X: " + b"a" * 20000 + b"\r\n\r\n"
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.bound_port)
        writer.write(head)
        with contextlib.suppress(ConnectionError):
            await writer.drain()
        data = await asyncio.wait_for(reader.read(-1), timeout=5)
        writer.close()
        proxy.server.close()
        return data, calls

    data, calls = run(scenario())
    assert not data.startswith(b"HTTP/1.1 200")
    assert calls == []


def test_concurrency_cap_returns_503():
    async def scenario():
        upstream = Upstream("silent")
        up_port = await upstream.start()
        proxy, _ = await _proxy(up_port, max_connections=1)
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.bound_port)
        writer.write(f"CONNECT github.com:{up_port} HTTP/1.1\r\n\r\n".encode())
        first = await reader.readuntil(b"\r\n\r\n")
        second, _ = await _request(
            proxy.bound_port, f"CONNECT github.com:{up_port} HTTP/1.1\r\n\r\n".encode()
        )
        writer.close()
        proxy.server.close()
        upstream.server.close()
        return first, second

    first, second = run(scenario())
    assert first.startswith(b"HTTP/1.1 200")
    assert second.startswith(b"HTTP/1.1 503")
