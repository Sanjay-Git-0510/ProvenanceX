"""Asyncio CONNECT proxy implementing the egress policy (app/egress_proxy/policy.py).

Per connection:
  1. read the request head (at most 8 KiB, within HEADER_TIMEOUT); only `CONNECT host:443`
     is accepted. Plain-HTTP proxying (GET http://...) is refused with 405: HTTPS only.
  2. check the host name against the exact allowlist and the port against the allowed ports.
  3. resolve the name ONCE (within the connect timeout); refuse if any address is not public.
  4. connect to a validated address (never re-resolving), reply 200, and relay bytes both ways
     with an idle timeout, a total tunnel duration and byte caps in each direction.
  Nothing from the client's request head is forwarded upstream (no headers, no credentials).
  Concurrency is capped; past the cap new tunnels get 503.

Redirects: TLS is end to end, so the proxy cannot see HTTP redirects. Every redirect target is
a new CONNECT and is checked here again; the fetcher also validates each redirect hop itself.

Every tunnel ends with one JSON log line (client, host, port, address, outcome, bytes, seconds).
"""

import asyncio
import json
import logging
import socket
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from app.egress_proxy.policy import Denied, Policy

logger = logging.getLogger("egress_proxy")

MAX_HEAD_BYTES = 8192
CHUNK = 65536
Resolver = Callable[[str, int], Awaitable[list[str]]]


@dataclass
class ProxyConfig:
    policy: Policy
    host: str = "0.0.0.0"  # noqa: S104 - listens only on the internal fetch network in Compose
    port: int = 3128
    header_timeout: float = 10.0
    connect_timeout: float = 10.0
    idle_timeout: float = 60.0
    max_tunnel_seconds: float = 900.0
    max_down_bytes: int = 512 * 1024 * 1024
    max_up_bytes: int = 8 * 1024 * 1024
    max_connections: int = 32
    resolver: Resolver | None = None
    # Test hook: the address check. Production always uses Policy.check_addresses.
    address_check: Callable[[list[str]], list[str]] = field(default=Policy.check_addresses)


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


class _Tunnel:
    def __init__(self) -> None:
        self.started = time.monotonic()
        self.host = ""
        self.port = 0
        self.address = ""
        self.up = 0
        self.down = 0
        self.outcome = "refused"
        self.reason = ""


class EgressProxy:
    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        self.resolver = config.resolver or system_resolver
        self._slots = asyncio.Semaphore(config.max_connections)
        self.server: asyncio.base_events.Server | None = None

    async def start(self) -> asyncio.base_events.Server:
        self.server = await asyncio.start_server(
            self._handle, self.config.host, self.config.port, limit=MAX_HEAD_BYTES * 2
        )
        return self.server

    @property
    def bound_port(self) -> int:
        assert self.server is not None  # noqa: S101
        return self.server.sockets[0].getsockname()[1]

    # ------------------------------------------------------------------ helpers
    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, status: int, text: str) -> None:
        body = f"{text}\n".encode()
        writer.write(
            f"HTTP/1.1 {status} {text}\r\nContent-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        try:
            await writer.drain()
        except (ConnectionError, OSError):
            pass

    async def _read_head(self, reader: asyncio.StreamReader) -> bytes:
        head = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"), timeout=self.config.header_timeout
        )
        if len(head) > MAX_HEAD_BYTES:
            raise Denied("request head is too large")
        return head

    @staticmethod
    def _parse_connect(head: bytes) -> tuple[str, int]:
        line = head.split(b"\r\n", 1)[0].decode("ascii", "strict")
        parts = line.split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
            raise Denied("malformed request line")
        method, target, _ = parts
        if method != "CONNECT":
            raise _MethodNotAllowed()
        host, sep, port_text = target.rpartition(":")
        if not sep or not port_text.isdigit() or len(port_text) > 5:
            raise Denied("CONNECT target must be host:port")
        if host.startswith("["):
            raise Denied("IP address targets are not allowed")
        return host, int(port_text)

    # ------------------------------------------------------------------ handling
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        tunnel = _Tunnel()
        peer = writer.get_extra_info("peername")
        client = str(peer[0]) if peer else "?"
        if self._slots.locked():
            tunnel.reason = "too many concurrent tunnels"
            await self._reply(writer, 503, "Service Unavailable")
            await self._close(writer)
            self._log(client, tunnel)
            return
        async with self._slots:
            try:
                await self._serve(reader, writer, tunnel)
            except _MethodNotAllowed:
                tunnel.reason = "only HTTPS CONNECT tunnels are allowed"
                await self._reply(writer, 405, "Method Not Allowed")
            except Denied as exc:
                tunnel.reason = exc.reason
                await self._reply(writer, 403, "Forbidden")
            except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                tunnel.reason = tunnel.reason or "client sent no complete request in time"
                if tunnel.outcome == "refused":
                    await self._reply(writer, 408, "Request Timeout")
            except UnicodeDecodeError:
                tunnel.reason = "malformed request"
                await self._reply(writer, 400, "Bad Request")
            except (ConnectionError, OSError) as exc:
                tunnel.reason = tunnel.reason or f"connection error ({exc.__class__.__name__})"
            finally:
                await self._close(writer)
                self._log(client, tunnel)

    async def _serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tunnel: _Tunnel
    ) -> None:
        head = await self._read_head(reader)
        host, port = self._parse_connect(head)
        tunnel.host, tunnel.port = host[:253], port
        name = self.config.policy.check_target(host, port)
        try:
            addresses = await asyncio.wait_for(
                self.resolver(name, port), timeout=self.config.connect_timeout
            )
        except (OSError, TimeoutError) as exc:
            raise Denied("the host name did not resolve") from exc
        # Every address must be public; then connect only to those validated addresses.
        validated = self.config.address_check(list(addresses))
        upstream: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
        for address in validated:
            try:
                upstream = await asyncio.wait_for(
                    asyncio.open_connection(address, port), timeout=self.config.connect_timeout
                )
            except (OSError, TimeoutError):
                continue
            tunnel.address = address
            break
        if upstream is None:
            tunnel.reason = "upstream connection failed"
            await self._reply(writer, 502, "Bad Gateway")
            return
        up_reader, up_writer = upstream
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        tunnel.outcome = "tunneled"
        try:
            await self._relay(reader, writer, up_reader, up_writer, tunnel)
        finally:
            await self._close(up_writer)

    async def _relay(
        self,
        client_r: asyncio.StreamReader,
        client_w: asyncio.StreamWriter,
        up_r: asyncio.StreamReader,
        up_w: asyncio.StreamWriter,
        tunnel: _Tunnel,
    ) -> None:
        deadline = tunnel.started + self.config.max_tunnel_seconds

        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter, upward: bool) -> None:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    tunnel.reason = "tunnel exceeded its maximum duration"
                    return
                chunk = await asyncio.wait_for(
                    src.read(CHUNK), timeout=min(self.config.idle_timeout, remaining)
                )
                if not chunk:
                    return
                if upward:
                    tunnel.up += len(chunk)
                    if tunnel.up > self.config.max_up_bytes:
                        tunnel.reason = "upload byte cap exceeded"
                        return
                else:
                    tunnel.down += len(chunk)
                    if tunnel.down > self.config.max_down_bytes:
                        tunnel.reason = "download byte cap exceeded"
                        return
                dst.write(chunk)
                await dst.drain()

        tasks = [
            asyncio.create_task(pump(client_r, up_w, True)),
            asyncio.create_task(pump(up_r, client_w, False)),
        ]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                exc = task.exception()
                if isinstance(exc, TimeoutError):
                    tunnel.reason = tunnel.reason or "idle timeout"
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        if tunnel.reason:
            tunnel.outcome = "cut"

    @staticmethod
    async def _close(writer: asyncio.StreamWriter) -> None:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
        except (ConnectionError, OSError, TimeoutError):
            pass

    @staticmethod
    def _log(client: str, tunnel: _Tunnel) -> None:
        logger.info(
            json.dumps(
                {
                    "client": client,
                    "host": tunnel.host,
                    "port": tunnel.port,
                    "address": tunnel.address,
                    "outcome": tunnel.outcome,
                    "reason": tunnel.reason,
                    "bytes_up": tunnel.up,
                    "bytes_down": tunnel.down,
                    "seconds": round(time.monotonic() - tunnel.started, 3),
                }
            )
        )


class _MethodNotAllowed(Exception):  # noqa: N818
    pass
