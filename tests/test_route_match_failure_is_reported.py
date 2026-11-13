"""A route whose matches() raises is logged and flagged unresolved, so the engine
answers the request as an unresolved route; it never quietly drops the decorator."""

import logging
from typing import Any

import pytest
from fastapi import FastAPI
from guard_core.models import SecurityConfig
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import BaseRoute, Match

import guard.middleware
from guard import SecurityDecorator
from guard.asgi import PureASGISecurityMiddleware
from guard.middleware import SecurityMiddleware


@pytest.fixture(autouse=True)
def _fresh_failure_samples() -> None:
    getattr(guard.middleware, "_route_match_failure_samples", {}).clear()


CLASSES = pytest.mark.parametrize(
    "middleware_class",
    [SecurityMiddleware, PureASGISecurityMiddleware],
    ids=["classic", "pure"],
)


class Exploding(BaseRoute):
    def matches(self, scope: Any) -> tuple[Match, Any]:
        raise RuntimeError("matches blew up")

    async def handle(self, scope: Any, receive: Any, send: Any) -> None:
        return None


def _app(middleware_class: Any, **config: Any) -> FastAPI:
    settings = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        enable_rate_limiting=False,
        enable_penetration_detection=False,
        ban_on_hostile_signals=False,
        **config,
    )
    app = FastAPI()
    decorator = SecurityDecorator(settings)
    app.state.guard_decorator = decorator

    @decorator.require_ip(whitelist=["10.1.1.1"])
    async def walled(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    app.router.routes.insert(0, Exploding())
    app.add_api_route("/walled", walled, methods=["GET"])
    app.add_middleware(middleware_class, config=settings)
    return app


def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app, client=("127.0.0.1", 50000)),
        base_url="http://testserver",
    )


@CLASSES
async def test_a_raising_route_is_logged_with_its_traceback(
    middleware_class: Any, caplog: pytest.LogCaptureFixture
) -> None:
    async with _client(_app(middleware_class)) as client:
        with caplog.at_level(logging.ERROR):
            await client.get("/walled")

    logged = [r for r in caplog.records if "Exploding.matches raised" in r.getMessage()]
    assert len(logged) == 1
    assert logged[0].exc_info is not None


@CLASSES
async def test_a_raising_route_flags_the_request_unresolved_for_the_engine(
    middleware_class: Any,
) -> None:
    app = _app(middleware_class, route_resolution_strict=True)
    async with _client(app) as client:
        response = await client.get("/walled")

    assert response.status_code == 500


@CLASSES
async def test_a_raising_route_keeps_the_matching_routes_decorator_when_not_strict(
    middleware_class: Any,
) -> None:
    app = _app(middleware_class, route_resolution_strict=False)
    async with _client(app) as client:
        response = await client.get("/walled")

    assert response.status_code == 403
