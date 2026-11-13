"""Guard's CORS headers replace the response's of the same name, and `Vary` is
merged, whichever of the four places adds them."""

from typing import Any

import pytest
from fastapi import FastAPI
from guard_core.models import SecurityConfig
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from guard.asgi import PureASGISecurityMiddleware
from guard.middleware import SecurityMiddleware

ORIGIN = "https://good.example"
OWN = {"Access-Control-Allow-Origin": "https://own.example", "Vary": "Accept"}

CLASSES = pytest.mark.parametrize(
    "middleware_class",
    [SecurityMiddleware, PureASGISecurityMiddleware],
    ids=["classic", "pure"],
)


def _config(**overrides: Any) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        enable_rate_limiting=False,
        enable_penetration_detection=False,
        ban_on_hostile_signals=False,
        enable_cors=True,
        cors_allow_origins=[ORIGIN],
        **overrides,
    )


def _app(middleware_class: Any, config: SecurityConfig) -> FastAPI:
    app = FastAPI()

    @app.get("/own")
    async def own() -> JSONResponse:
        return JSONResponse({"ok": True}, headers=OWN)

    app.add_middleware(middleware_class, config=config)
    return app


async def _get(app: FastAPI) -> Any:
    transport = ASGITransport(app=app, client=("127.0.0.1", 50000))
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.get("/own", headers={"Origin": ORIGIN})


def _vary_tokens(response: Any) -> set[str]:
    values = ",".join(response.headers.get_list("vary"))
    return {token.strip().lower() for token in values.split(",")}


@CLASSES
async def test_the_response_pass_replaces_the_apps_cors_header(
    middleware_class: Any,
) -> None:
    response = await _get(_app(middleware_class, _config()))

    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert {"accept", "origin"} <= _vary_tokens(response)


async def test_the_streamed_downstream_replaces_the_apps_cors_header() -> None:
    config = _config(custom_response_modifier=lambda response: response)
    response = await _get(_app(PureASGISecurityMiddleware, config))

    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert {"accept", "origin"} <= _vary_tokens(response)


async def test_a_pure_middleware_response_replaces_the_apps_cors_header() -> None:
    config = _config()
    middleware = PureASGISecurityMiddleware(FastAPI(), config=config)
    sent: list[dict[str, Any]] = []

    async def send(message: Any) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/own",
        "headers": [(b"origin", ORIGIN.encode())],
        "query_string": b"",
    }
    response = Response("x", headers=OWN)
    await middleware._send_response(response, Request(scope), send)

    headers = {k.decode(): v.decode() for k, v in sent[0]["headers"]}
    assert headers["access-control-allow-origin"] == ORIGIN
    assert {"accept", "origin"} <= {
        t.strip().lower() for t in headers["vary"].split(",")
    }
