import logging
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.models import SecurityConfig
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Host, Route

from guard.middleware import SecurityMiddleware


async def _ok(request: Any) -> JSONResponse:
    return JSONResponse({"ok": True})


async def _opaque_app(scope: Any, receive: Any, send: Any) -> None:
    await JSONResponse({"opaque": True})(scope, receive, send)


def _app(entries: list[str], *, host_route: bool = False) -> FastAPI:
    app = FastAPI()
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        exclude_paths=entries,
        ban_on_hostile_signals=False,
        passive_mode=False,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/health")
    async def health() -> dict[str, int]:
        return {"h": 1}

    @app.get("/items/{item_id}")
    async def item(item_id: int) -> dict[str, int]:
        return {"item": item_id}

    app.mount("/admin", Starlette(routes=[Route("/panel", _ok)]))
    app.mount("/files", _opaque_app)
    if host_route:
        app.router.routes.append(Host("example.test", Starlette(routes=[])))
    return app


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "guard_core.models" and "exclude_paths entry" in r.getMessage()
    ]


def _typo(entry: str) -> str:
    return (
        f"exclude_paths entry {entry!r} matches no registered route; check it for "
        "a typo."
    )


def test_only_a_typo_entry_warns_once_on_a_real_app(
    caplog: pytest.LogCaptureFixture,
) -> None:
    entries = [
        "/docs",
        "/health",
        "/items",
        "/items/7",
        "/admin",
        "/admin/panel",
        "/admin/typo",
        "/files/deep/er",
        "/static",
        "/typo",
    ]
    app = _app(entries)
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        with TestClient(app, client=("127.0.0.1", 5555)) as client:
            for _ in range(3):
                client.get("/health")

    assert _warnings(caplog) == [_typo("/admin/typo"), _typo("/typo")]


def test_a_host_route_counts_as_a_match_so_the_warning_is_never_false(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app(["/anything"], host_route=True)
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        with TestClient(app, client=("127.0.0.1", 5555)) as client:
            client.get("/health")

    assert _warnings(caplog) == []


def test_the_prefixes_are_the_open_root_before_the_app_is_known() -> None:
    config = SecurityConfig(enable_redis=False, ban_on_hostile_signals=False)
    middleware = SecurityMiddleware(FastAPI(), config=config)

    assert middleware.static_route_prefixes() == ("/",)


def test_mounts_and_routes_are_listed_with_their_open_ended_heads() -> None:
    app = _app([])
    with TestClient(app, client=("127.0.0.1", 5555)) as client:
        client.get("/health")
    node: Any = app.middleware_stack
    while not isinstance(node, SecurityMiddleware):
        node = node.app

    prefixes = node.static_route_prefixes()

    assert {"/health", "/items/", "/admin", "/admin/panel", "/files", "/files/"} <= set(
        prefixes
    )
