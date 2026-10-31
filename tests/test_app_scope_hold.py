import os
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi import FastAPI
from guard_core._utils.app_scope import _current_app_scope, app_scope_of
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.redis_handler import RedisManager
from httpx import ASGITransport, AsyncClient
from starlette.types import Receive, Scope, Send

from guard import PureASGISecurityMiddleware, SecurityConfig, SecurityMiddleware

REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"
PROXY = "10.0.0.1"
MIDDLEWARES = [SecurityMiddleware, PureASGISecurityMiddleware]


def _config(prefix: str, proxies: list[str]) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        trusted_proxies=tuple(proxies),
        enable_rate_limiting=False,
        enable_penetration_detection=False,
    )


def _app(middleware: Any, config: SecurityConfig, seen: dict[str, Any]) -> FastAPI:
    app = FastAPI()
    app.add_middleware(middleware, config=config)

    @app.get("/ban")
    async def ban() -> dict[str, bool]:
        manager = ip_ban_manager_for(config)
        seen["scope"] = _current_app_scope.get()
        seen["banned"] = await manager.ban_ip(PROXY, 60)
        return {"ok": True}

    return app


async def _get(app: Any, path: str) -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.get(path)).status_code == 200


@pytest.fixture
async def cleanup() -> AsyncIterator[list[SecurityConfig]]:
    configs: list[SecurityConfig] = []
    yield configs
    for config in configs:
        manager = ip_ban_manager_for(config)
        await manager.unban_ip(PROXY, config=config)
        if isinstance(manager.redis_handler, RedisManager):
            await manager.redis_handler.close()


@pytest.mark.parametrize("middleware", MIDDLEWARES)
async def test_a_ban_in_a_route_handler_goes_through_the_routes_own_app(
    middleware: Any, cleanup: list[SecurityConfig]
) -> None:
    prefix = f"wp136-hold-{middleware.__name__}:"
    config_a, config_b = _config(prefix, [PROXY]), _config(prefix, [])
    cleanup.extend([config_a, config_b])
    seen_a: dict[str, Any] = {}
    seen_b: dict[str, Any] = {}
    app_a = _app(middleware, config_a, seen_a)
    app_b = _app(middleware, config_b, seen_b)

    await _get(app_a, "/ban")
    await _get(app_b, "/ban")
    await _get(app_a, "/ban")

    assert seen_a["scope"] is app_scope_of(config_a)
    assert seen_b["scope"] is app_scope_of(config_b)
    assert seen_a["banned"] is False
    assert seen_b["banned"] is True
    assert _current_app_scope.get() is None


class _AfterSubApp:
    def __init__(self, app: Any, seen: list[Any]) -> None:
        self.app = app
        self.seen = seen

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)
        self.seen.append(_current_app_scope.get())


@pytest.mark.parametrize("middleware", MIDDLEWARES)
async def test_a_mounted_sub_app_hands_back_the_outer_apps_scope(
    middleware: Any,
) -> None:
    prefix = f"wp136-mount-{middleware.__name__}:"
    config_outer, config_inner = _config(prefix, [PROXY]), _config(prefix, [])
    inner = _app(middleware, config_inner, {})
    after: list[Any] = []
    outer = FastAPI()
    outer.add_middleware(middleware, config=config_outer)
    outer.mount("/sub", _AfterSubApp(inner, after))

    await _get(outer, "/sub/ban")

    assert after == [app_scope_of(config_outer)]
    assert _current_app_scope.get() is None
