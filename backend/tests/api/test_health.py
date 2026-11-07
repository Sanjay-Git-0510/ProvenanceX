def test_liveness_ok(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["version"]


def test_readiness_ok_when_db_reachable(client):
    resp = client.get("/api/v1/health/ready")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready", "db": "ok", "version": resp.json()["version"]}


def test_readiness_structured_503_when_db_down(client_db_down):
    resp = client_db_down.get("/api/v1/health/ready")
    assert resp.status_code == 503
    err = resp.json()["error"]
    assert err["code"] == "database_unavailable"
    assert err["message"]
    # No internal exception text leaks to the client.
    assert "connection refused" not in resp.text


def test_unknown_route_returns_structured_404(client):
    resp = client.get("/api/v1/does-not-exist")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"
