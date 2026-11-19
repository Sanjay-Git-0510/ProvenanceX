"""The real egress-proxy container (PROVENANCEX_SANDBOX_TESTS=1). Clients run in throwaway
containers on the internal fetch network, exactly where fetchers run.

Offline tests: policy refusals (no DNS lookup is made for them). `network` tests
(PROVENANCEX_NETWORK_TESTS=1): real GitHub/Hugging Face TLS through the tunnel, the real Hugging
Face redirect chain hop by hop, names in public DNS that point at internal addresses (SSRF and
rebinding-style records), and the per-tunnel byte cap.
"""

import json
import textwrap

import pytest

from tests.live_helpers import PROXY_IMAGE, FetchNet, fetch_network, image_present

pytestmark = pytest.mark.sandbox

CLIENT = textwrap.dedent(
    """
    import json, socket, ssl, sys
    from urllib.parse import urljoin, urlsplit

    def connect(host, port=443):
        s = socket.create_connection(("egress-proxy", 3128), timeout=20)
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\\r\\nHost: {host}:{port}\\r\\n\\r\\n".encode())
        head = b""
        while b"\\r\\n\\r\\n" not in head:
            chunk = s.recv(1024)
            if not chunk:
                break
            head += chunk
        return s, head.split(b"\\r\\n", 1)[0].decode()

    def get(url, max_bytes=None):
        parts = urlsplit(url)
        sock, status = connect(parts.hostname)
        if " 200 " not in status:
            return {"proxy": status}
        tls = ssl.create_default_context().wrap_socket(sock, server_hostname=parts.hostname)
        path = parts.path + ("?" + parts.query if parts.query else "")
        tls.sendall(f"GET {path} HTTP/1.1\\r\\nHost: {parts.hostname}\\r\\n"
                    "User-Agent: px-live-test\\r\\nConnection: close\\r\\n\\r\\n".encode())
        data = b""
        try:
            while chunk := tls.recv(65536):
                data += chunk
        except (ssl.SSLError, OSError) as e:
            return {"proxy": status, "cut": type(e).__name__, "received": len(data)}
        head, _, body = data.partition(b"\\r\\n\\r\\n")
        lines = head.decode("latin-1").split("\\r\\n")
        headers = {k.lower(): v for k, _, v in (l.partition(": ") for l in lines[1:])}
        return {"proxy": status, "status": lines[0], "location": headers.get("location"),
                "received": len(data)}

    mode, arg = sys.argv[1], sys.argv[2]
    if mode == "connect":
        sock, status = connect(arg)
        print(json.dumps({"proxy": status}))
    elif mode == "get":
        print(json.dumps(get(arg)))
    elif mode == "chain":
        hops, url = [], arg
        for _ in range(5):
            r = get(url); r["url_host"] = urlsplit(url).hostname; hops.append(r)
            loc = r.get("location")
            if not loc or not r.get("status", "").split()[1].startswith("3"):
                break
            url = urljoin(url, loc)
        print(json.dumps(hops))
    """
)


@pytest.fixture(scope="module", autouse=True)
def _image():
    if not image_present(PROXY_IMAGE):
        pytest.fail(f"{PROXY_IMAGE} is not built")


def _client(net: FetchNet, mode: str, arg: str):
    out = net.run_on_fetch_net(CLIENT.replace("sys.argv[1], sys.argv[2]", f"{mode!r}, {arg!r}"),
                               timeout=120)  # fmt: skip
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def net():
    with fetch_network() as n:
        yield n


# --------------------------------------------------------------------------- offline
@pytest.mark.parametrize(
    "target",
    [
        "evil.example.com",  # not on the allowlist
        "api.github.com",  # no implied subdomains
        "huggingface.co.evil.com",
        "169.254.169.254",  # metadata by IP
        "127.0.0.1",
        "[::1]",
        "postgres",  # internal Compose service names
        "api",
        "hardhat",
        "localhost",
    ],
)
def test_unapproved_destinations_are_refused(net, target):
    assert _client(net, "connect", target)["proxy"].startswith("HTTP/1.1 403")
    events = [e for e in net.proxy_logs() if e.get("outcome") == "refused"]
    assert events and events[-1]["address"] == ""  # never connected anywhere


def test_plain_http_proxying_is_refused(net):
    out = net.run_on_fetch_net(
        "import socket; s=socket.create_connection(('egress-proxy',3128),5);"
        "s.sendall(b'GET http://github.com/ HTTP/1.1\\r\\nHost: github.com\\r\\n\\r\\n');"
        "print(s.recv(64))"
    )
    assert "405" in out.stdout


def test_non_https_port_is_refused(net):
    assert _client(net, "connect", "github.com:80".rsplit(":", 1)[0] + ":80")["proxy"].startswith(
        "HTTP/1.1 403"
    )


# --------------------------------------------------------------------------- network
@pytest.mark.network
def test_github_tls_works_through_the_tunnel(net):
    r = _client(
        net, "get", "https://github.com/octocat/Hello-World.git/info/refs?service=git-upload-pack"
    )
    assert r["proxy"].startswith("HTTP/1.1 200")
    assert r["status"].startswith("HTTP/1.1 200")


@pytest.mark.network
def test_real_hugging_face_redirect_chain_is_followed_hop_by_hop(net):
    """LFS: huggingface.co -302-> us.aws.cdn.hf.co; small file: 307 to huggingface.co itself."""
    lfs = _client(
        net, "chain",
        "https://huggingface.co/sshleifer/tiny-gpt2/resolve/"
        "5f91d94bd9cd7190a9f3216ff93cd1dd95f2c7be/pytorch_model.bin",
    )  # fmt: skip
    assert [h["url_host"] for h in lfs][:2] == ["huggingface.co", "us.aws.cdn.hf.co"]
    assert lfs[-1]["status"].startswith("HTTP/1.1 200")
    small = _client(
        net, "chain",
        "https://huggingface.co/sshleifer/tiny-gpt2/resolve/"
        "5f91d94bd9cd7190a9f3216ff93cd1dd95f2c7be/config.json",
    )  # fmt: skip
    assert {h["url_host"] for h in small} == {"huggingface.co"}
    assert small[-1]["status"].startswith("HTTP/1.1 200")


@pytest.mark.network
def test_redirect_to_a_host_off_the_allowlist_is_refused(net):
    """GitHub redirects /octocat/Hello-World/raw/... to raw.githubusercontent.com, which is not
    allowlisted: the next hop's CONNECT must be refused."""
    hops = _client(
        net, "chain",
        "https://github.com/octocat/Hello-World/raw/7fd1a60b01f91b314f59955a4e4d4e80d8edf11d/README",
    )  # fmt: skip
    assert hops[0]["status"].split()[1].startswith("3")
    assert hops[1]["url_host"] == "raw.githubusercontent.com"
    assert hops[1]["proxy"].startswith("HTTP/1.1 403")


@pytest.mark.network
@pytest.mark.parametrize(
    "name",
    [
        "localtest.me",  # public DNS record -> 127.0.0.1
        "169.254.169.254.nip.io",  # public DNS record -> the metadata service
        "10.0.0.1.nip.io",  # -> RFC 1918
        "127.0.0.1.nip.io",
    ],
)
def test_allowlisted_names_resolving_inside_are_refused(name):
    """Even an allowlisted name is refused when real DNS points it at an internal address."""
    with fetch_network(name) as net:
        r = _client(net, "connect", name)
        events = net.proxy_logs()
    assert r["proxy"].startswith("HTTP/1.1 403")
    assert any(
        e.get("host") == name
        and "non-public" in e.get("reason", "")
        or "did not resolve" in e.get("reason", "")
        for e in events
    ), events


@pytest.mark.network
def test_tunnel_byte_cap_cuts_an_oversized_download():
    with fetch_network(proxy_env={"EGRESS_MAX_TUNNEL_MB": "1"}) as net:
        r = _client(
            net, "chain",
            "https://huggingface.co/sshleifer/tiny-gpt2/resolve/"
            "5f91d94bd9cd7190a9f3216ff93cd1dd95f2c7be/pytorch_model.bin",  # 2.5 MB
        )  # fmt: skip
        events = net.proxy_logs()
    last = r[-1]
    assert last["received"] <= 1024 * 1024 + 2 * 65536
    assert any(e.get("reason") == "download byte cap exceeded" for e in events), events
