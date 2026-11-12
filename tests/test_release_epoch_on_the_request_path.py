"""LEDGER 6.793 / D-317 amendment 2: a request on an app that was released rebinds
and initializes it before it decides, once, whatever the number of first requests."""

import asyncio
import time
import uuid
from typing import Any

import pytest
from fastapi import FastAPI
from guard_core import release_app
from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers._ipban_bans import _VERSION_PAIR
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from httpx import ASGITransport, AsyncClient

from guard._middleware_state import get_state
from guard.middleware import SecurityMiddleware
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL

CLIENT = ("203.0.113.9", 4321)


def _config(**overrides: Any) -> SecurityConfig:
    settings: dict[str, Any] = {"enable_redis": False, "enable_agent": False}
    settings.update(overrides)
    return SecurityConfig(**settings)


def _app(config: SecurityConfig) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def root() -> dict[str, bool]:
        return {"ok": True}

    return app


def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app, client=CLIENT), base_url="http://t")


def _limiter_managers(app: FastAPI, config: SecurityConfig) -> list[Any]:
    state = get_state(config, None, app)
    assert state is not None and state.security_pipeline is not None
    return [
        check.ip_ban_manager
        for check in state.security_pipeline.checks
        if isinstance(check, RateLimitCheck)
    ]


async def test_a_late_request_rebinds_and_its_ban_lands_on_its_own_manager() -> None:
    config = _config()
    app = _app(config)
    other_config = _config()
    async with _client(app) as client:
        assert (await client.get("/")).status_code == 200
        release_app(config)
        assert (
            ip_ban_manager_for(other_config, bind=True) is ipban_module.ip_ban_manager
        )
        try:
            assert (await client.get("/")).status_code == 200
            own = ip_ban_manager_for(config)
            assert own is not ipban_module.ip_ban_manager
            managers = _limiter_managers(app, config)
            assert managers
            assert all(manager is own for manager in managers)
            await managers[0].ban_ip("198.51.100.7", 60, "pin")
            assert await own.is_ip_banned("198.51.100.7")
            assert not await ipban_module.ip_ban_manager.is_ip_banned("198.51.100.7")
        finally:
            release_app(other_config)


async def test_two_concurrent_first_requests_after_a_release_initialize_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    app = _app(config)
    async with _client(app) as client:
        assert (await client.get("/")).status_code == 200
        state = get_state(config, None, app)
        assert state is not None
        initializer = state.handler_initializer
        calls: list[float] = []

        async def counted_initialize() -> None:
            calls.append(time.monotonic())
            await asyncio.sleep(0.1)

        monkeypatch.setattr(
            initializer, "initialize_redis_handlers", counted_initialize
        )
        release_app(config)
        responses = await asyncio.gather(client.get("/"), client.get("/"))
    assert [response.status_code for response in responses] == [200, 200]
    assert len(calls) == 1


async def test_a_ban_another_worker_wrote_in_redis_is_refused_after_a_release() -> None:
    config = _config(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"{REDIS_PREFIX}wp620r3:{uuid.uuid4().hex[:8]}:",
    )
    app = _app(config)
    async with _client(app) as client:
        assert (await client.get("/")).status_code == 200
        release_app(config)
        worker = RedisManager(
            SecurityConfig(
                enable_redis=True,
                redis_url=config.redis_url,
                redis_prefix=config.redis_prefix,
                enable_agent=False,
            )
        )
        await worker.initialize()
        try:
            await worker.write_ban_extending_only(
                "banned_ips",
                CLIENT[0],
                str(time.time() + 300),
                300,
                version=_VERSION_PAIR,
            )
            assert (await client.get("/")).status_code == 403
            assert ip_ban_manager_for(config).redis_handler is not None
        finally:
            await worker.close()
