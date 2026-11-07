from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.errors import AppError, error_body, register_error_handlers


def _app() -> FastAPI:
    app = FastAPI()
    register_error_handlers(app)

    @app.get("/app-error")
    def app_error():
        raise AppError("bad_input", "Input rejected", status_code=400, details={"field": "url"})

    @app.get("/crash")
    def crash():
        raise RuntimeError("secret internal detail")

    @app.get("/typed")
    def typed(n: int):
        return {"n": n}

    return app


def test_error_body_shape():
    assert error_body("c", "m") == {"error": {"code": "c", "message": "m", "details": None}}


def test_app_error_envelope():
    resp = TestClient(_app()).get("/app-error")
    assert resp.status_code == 400
    assert resp.json() == error_body("bad_input", "Input rejected", {"field": "url"})


def test_unhandled_error_is_generic_500():
    resp = TestClient(_app(), raise_server_exceptions=False).get("/crash")
    assert resp.status_code == 500
    assert resp.json()["error"]["code"] == "internal_error"
    assert "secret internal detail" not in resp.text


def test_validation_error_envelope():
    resp = TestClient(_app()).get("/typed", params={"n": "abc"})
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "validation_error"
    assert err["details"][0]["loc"] == ["query", "n"]
