"""`python -m app.egress_proxy` (the egress-proxy container), or `--healthcheck`.

Configuration (environment, all optional except the allowlist):
  EGRESS_ALLOWED_HOSTS            comma-separated exact host names (required)
  EGRESS_ALLOWED_PORTS            comma-separated ports (default 443)
  EGRESS_LISTEN_PORT              default 3128
  EGRESS_CONNECT_TIMEOUT_SECONDS  DNS + TCP connect, default 10
  EGRESS_IDLE_TIMEOUT_SECONDS     default 60
  EGRESS_MAX_TUNNEL_SECONDS       default 900
  EGRESS_MAX_TUNNEL_MB            bytes downloaded per tunnel, default 512
  EGRESS_MAX_CONNECTIONS          concurrent tunnels, default 32
"""

import asyncio
import logging
import os
import socket
import sys

from app.egress_proxy.policy import Policy
from app.egress_proxy.server import EgressProxy, ProxyConfig


def _int(name: str, default: int) -> int:
    value = int(os.environ.get(name, default))
    if value <= 0:
        raise SystemExit(f"{name} must be positive")
    return value


def config_from_env() -> ProxyConfig:
    hosts = [h for h in os.environ.get("EGRESS_ALLOWED_HOSTS", "").split(",") if h.strip()]
    ports = [int(p) for p in os.environ.get("EGRESS_ALLOWED_PORTS", "443").split(",") if p]
    return ProxyConfig(
        policy=Policy.from_lists(hosts, ports),
        port=_int("EGRESS_LISTEN_PORT", 3128),
        connect_timeout=float(_int("EGRESS_CONNECT_TIMEOUT_SECONDS", 10)),
        idle_timeout=float(_int("EGRESS_IDLE_TIMEOUT_SECONDS", 60)),
        max_tunnel_seconds=float(_int("EGRESS_MAX_TUNNEL_SECONDS", 900)),
        max_down_bytes=_int("EGRESS_MAX_TUNNEL_MB", 512) * 1024 * 1024,
        max_connections=_int("EGRESS_MAX_CONNECTIONS", 32),
    )


def healthcheck() -> int:
    """Connect locally and expect the proxy's refusal of a non-CONNECT request."""
    port = _int("EGRESS_LISTEN_PORT", 3128)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            return 0 if sock.recv(64).startswith(b"HTTP/1.1 405") else 1
    except OSError:
        return 1


async def serve(config: ProxyConfig) -> None:
    proxy = EgressProxy(config)
    server = await proxy.start()
    logging.getLogger("egress_proxy").info(
        "egress proxy listening on %s:%s, allowlist=%s, ports=%s",
        config.host,
        proxy.bound_port,
        sorted(config.policy.allowed_hosts),
        sorted(config.policy.allowed_ports),
    )
    async with server:
        await server.serve_forever()


def main() -> int:
    if "--healthcheck" in sys.argv[1:]:
        return healthcheck()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    asyncio.run(serve(config_from_env()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
