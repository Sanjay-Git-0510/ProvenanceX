import httpx
import pytest

from app.scanners.vulns.http import HttpError, JsonHttpClient


def _client(handler, retries=2, max_bytes=10_000, sleeps=None):
    return JsonHttpClient(
        timeout_seconds=1,
        max_retries=retries,
        max_response_bytes=max_bytes,
        user_agent="ProvenanceX/test",
        transport=httpx.MockTransport(handler),
        sleep=(sleeps.append if sleeps is not None else lambda _s: None),
    )


def test_get_json_ok_and_user_agent():
    seen = {}

    def handler(request):
        seen["ua"] = request.headers["user-agent"]
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as c:
        assert c.get_json("https://x.test/a") == {"ok": True}
    assert seen["ua"] == "ProvenanceX/test"


def test_retries_on_503_then_succeeds_with_backoff():
    calls, sleeps = [], []

    def handler(request):
        calls.append(1)
        return httpx.Response(503) if len(calls) < 3 else httpx.Response(200, json=[1])

    with _client(handler, sleeps=sleeps) as c:
        assert c.post_json("https://x.test/b", {"q": 1}) == [1]
    assert len(calls) == 3
    assert sleeps == [0.5, 1.0]


def test_retry_after_honored_and_capped():
    calls, sleeps = [], []

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "3"})
        if len(calls) == 2:
            return httpx.Response(429, headers={"Retry-After": "9999"})
        return httpx.Response(200, json={})

    with _client(handler, sleeps=sleeps) as c:
        c.get_json("https://x.test")
    assert sleeps == [3.0, 10.0]


def test_gives_up_after_max_retries():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(502)

    with _client(handler, retries=1) as c, pytest.raises(HttpError) as exc:
        c.get_json("https://x.test")
    assert exc.value.kind == "status" and exc.value.status == 502
    assert len(calls) == 2


def test_4xx_not_retried():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(404)

    with _client(handler) as c, pytest.raises(HttpError) as exc:
        c.get_json("https://x.test")
    assert exc.value.status == 404 and len(calls) == 1


def test_timeout_retried_then_raised():
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    with _client(handler, retries=1) as c, pytest.raises(HttpError) as exc:
        c.get_json("https://x.test")
    assert exc.value.kind == "timeout"


def test_network_error():
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    with _client(handler, retries=0) as c, pytest.raises(HttpError) as exc:
        c.get_json("https://x.test")
    assert exc.value.kind == "network"


def test_oversize_response_rejected_while_streaming():
    def handler(request):
        return httpx.Response(200, content=b"[" + b"1," * 10_000 + b"1]")

    with _client(handler, max_bytes=1000) as c, pytest.raises(HttpError) as exc:
        c.get_json("https://x.test")
    assert exc.value.kind == "too_large"


def test_declared_oversize_rejected():
    def handler(request):
        return httpx.Response(200, content=b"{}", headers={"Content-Length": "999999"})

    with _client(handler, max_bytes=1000) as c, pytest.raises(HttpError) as exc:
        c.get_json("https://x.test")
    assert exc.value.kind == "too_large"


@pytest.mark.parametrize("body", [b"<html>", b"[" * 100_000])
def test_invalid_json(body):
    def handler(request):
        return httpx.Response(200, content=body)

    with _client(handler, max_bytes=10**6) as c, pytest.raises(HttpError) as exc:
        c.get_json("https://x.test")
    assert exc.value.kind == "invalid_json"


def test_redirects_not_followed():
    def handler(request):
        return httpx.Response(302, headers={"Location": "https://evil.test/"})

    with _client(handler) as c, pytest.raises(HttpError) as exc:
        c.get_json("https://x.test")
    assert exc.value.kind == "status" and exc.value.status == 302
