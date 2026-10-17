from collections.abc import Callable
from typing import Any
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.models import SecurityConfig
from starlette.applications import Starlette
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse
from starlette.routing import Route, WebSocketRoute

from guard.adapters import StarletteGuardRequest
from guard.middleware import SecurityMiddleware


def _handler_factory(name: str) -> Callable[[], Any]:
    async def handler() -> dict[str, str]:
        return {"name": name}

    return handler


def _app(limits: dict[str, tuple[int, int]]) -> FastAPI:
    app = FastAPI()
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1000,
        endpoint_rate_limits=limits,
        passive_mode=False,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/login")
    async def login() -> dict[str, str]:
        return {"name": "login"}

    @app.get("/users/{user_id}")
    async def user(user_id: int) -> dict[str, int]:
        return {"user": user_id}

    app.add_api_route("/a", _handler_factory("a"))
    app.add_api_route("/b", _handler_factory("b"))

    async def inner(request: Any) -> JSONResponse:
        return JSONResponse({"inner": True})

    app.mount("/sub", Starlette(routes=[Route("/inner", inner)]))
    return app


def _statuses(app: FastAPI, paths: list[str]) -> list[int]:
    with TestClient(app, client=("127.0.0.1", 5555)) as client:
        return [client.get(path, follow_redirects=False).status_code for path in paths]


def test_trailing_slash_spelling_shares_the_route_limit() -> None:
    app = _app({"/login": (2, 60)})

    assert _statuses(app, ["/login", "/login/", "/login"]) == [200, 307, 429]


def test_concrete_id_key_stays_per_resource() -> None:
    app = _app({"/users/42": (1, 60)})

    assert _statuses(app, ["/users/42", "/users/7", "/users/7", "/users/42"]) == [
        200,
        200,
        200,
        429,
    ]


def test_endpoints_built_by_one_factory_do_not_share_a_limit() -> None:
    app = _app({"/a": (1, 60)})

    assert _statuses(app, ["/a", "/b", "/b", "/a"]) == [200, 200, 200, 429]


def test_mounted_sub_app_route_key_maps_to_its_route() -> None:
    app = _app({"/sub/inner": (1, 60)})

    assert _statuses(app, ["/sub/inner", "/sub/inner"]) == [200, 429]


def test_login_and_login_slash_keys_are_both_enforced() -> None:
    app = _app({"/login": (3, 60), "/login/": (1, 60)})

    assert _statuses(app, ["/login", "/login", "/login"]) == [200, 429, 429]


def test_key_the_router_cannot_resolve_still_limits_through_the_fallback() -> None:
    app = _app({"//login/.": (1, 60)})

    assert _statuses(app, ["/login", "/login"]) == [200, 429]


def _middleware(app: Any) -> SecurityMiddleware:
    middleware = SecurityMiddleware(app, config=SecurityConfig(enable_redis=False))
    middleware.security_pipeline = Mock(needs_route_identity=True)
    return middleware


def _request(app: Any, path: str, method: str = "GET") -> StarletteRequest:
    return StarletteRequest(
        {
            "type": "http",
            "method": method,
            "path": path,
            "query_string": b"",
            "headers": [],
            "server": ("localhost", 8000),
            "root_path": "",
            "app": app,
        }
    )


def test_resolve_route_returns_every_method_of_a_path_once() -> None:
    app = FastAPI()

    @app.get("/x")
    async def read_x() -> None: ...

    @app.post("/x")
    async def write_x() -> None: ...

    middleware = _middleware(app)
    middleware._populate_guard_state(
        StarletteGuardRequest(_request(app, "/x")), _request(app, "/x")
    )

    assert set(middleware.resolve_route("/x")) == {(read_x, ()), (write_x, ())}


def test_resolve_route_skips_websocket_routes() -> None:
    async def socket(websocket: Any) -> None: ...

    app = Starlette(routes=[WebSocketRoute("/ws", socket)])
    middleware = _middleware(app)
    middleware._routing_app = app

    assert middleware.resolve_route("/ws") == ()


def test_resolve_route_before_the_first_request_returns_nothing() -> None:
    middleware = SecurityMiddleware(
        FastAPI(), config=SecurityConfig(enable_redis=False)
    )

    assert middleware.resolve_route("/x") == ()


@pytest.mark.parametrize(
    "path", ["/login", "/users/5", "/a", "/b", "/sub/inner", "/login/"]
)
def test_request_identity_equals_the_identity_resolve_route_returns(path: str) -> None:
    app = _app({})
    middleware = _middleware(app)
    request = _request(app, path)
    guard_request = StarletteGuardRequest(request)

    middleware._populate_guard_state(guard_request, request)

    assert guard_request.state.guard_route_identity in middleware.resolve_route(path)


def test_request_identity_is_not_built_without_endpoint_limits() -> None:
    app = _app({})
    middleware = _middleware(app)
    middleware.security_pipeline = Mock(needs_route_identity=False)
    request = _request(app, "/login")
    guard_request = StarletteGuardRequest(request)

    middleware._populate_guard_state(guard_request, request)

    assert not hasattr(guard_request.state, "guard_route_identity")
