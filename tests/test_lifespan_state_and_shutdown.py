import os
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any

import pytest
import redis
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from guard_core.models import SecurityConfig

from guard.lifespan import guard_lifespan, make_lifespan
from guard.middleware import SecurityMiddleware

REDIS_BASE_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6538/13")


@pytest.fixture(autouse=True)
def _unbind_singleton_redis_handlers() -> Iterator[None]:
    from guard_core.handlers.cloud_handler import cloud_handler
    from guard_core.handlers.ipban_handler import ip_ban_manager
    from guard_core.handlers.ratelimit_handler import rate_limit_handler
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler

    yield
    ip_ban_manager.redis_handler = None
    sus_patterns_handler.redis_handler = None
    rate_limit_handler.redis_handler = None
    if cloud_handler._instance is not None:
        cloud_handler._instance.redis_handler = None


@asynccontextmanager
async def _yielding_state(app: FastAPI) -> AsyncIterator[dict[str, int]]:
    yield {"x": 1}


@asynccontextmanager
async def _yielding_nothing(app: FastAPI) -> AsyncIterator[None]:
    yield


def _app_reading_state(lifespan: Callable[[Any], Any]) -> FastAPI:
    app = FastAPI(lifespan=lifespan)
    app.add_middleware(SecurityMiddleware, config=SecurityConfig(enable_redis=False))

    @app.get("/x")
    async def read_x(request: Request) -> dict[str, object]:
        return {"x": getattr(request.state, "x", None)}

    return app


def test_make_lifespan_passes_through_the_state_the_wrapped_lifespan_yields() -> None:
    app = _app_reading_state(make_lifespan(_yielding_state))
    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        assert client.get("/x").json() == {"x": 1}


def test_make_lifespan_still_accepts_a_lifespan_that_yields_nothing() -> None:
    app = _app_reading_state(make_lifespan(_yielding_nothing))
    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        assert client.get("/x").json() == {"x": None}


@pytest.fixture
def client_name() -> str:
    return f"wp178-{uuid.uuid4().hex}"


@pytest.fixture
def own_clients(client_name: str) -> Iterator[Callable[[], int]]:
    probe = redis.Redis.from_url(REDIS_BASE_URL)
    try:
        yield lambda: sum(
            1 for c in probe.client_list() if c.get("name") == client_name
        )
    finally:
        probe.close()


def _redis_app(
    client_name: str,
    lifespan: Callable[[Any], AbstractAsyncContextManager[Any]],
) -> FastAPI:
    config = SecurityConfig(
        redis_url=f"{REDIS_BASE_URL}?client_name={client_name}",
        redis_prefix=f"{client_name}:",
        enable_redis=True,
    )
    app = FastAPI(lifespan=lifespan)
    app.add_middleware(SecurityMiddleware, config=config)
    return app


@pytest.mark.parametrize("lifespan", [guard_lifespan, make_lifespan(None)])
async def test_exit_closes_the_apps_own_redis_client(
    lifespan: Callable[[Any], AbstractAsyncContextManager[Any]],
    client_name: str,
    own_clients: Callable[[], int],
) -> None:
    app = _redis_app(client_name, lifespan)
    assert own_clients() == 0
    async with lifespan(app):
        assert own_clients() >= 1
    assert own_clients() == 0


@pytest.mark.parametrize("lifespan", [guard_lifespan, make_lifespan(None)])
async def test_two_apps_on_one_connection_close_it_when_the_last_one_exits(
    lifespan: Callable[[Any], AbstractAsyncContextManager[Any]],
    client_name: str,
    own_clients: Callable[[], int],
) -> None:
    app_a = _redis_app(client_name, lifespan)
    app_b = _redis_app(client_name, lifespan)
    async with lifespan(app_a):
        async with lifespan(app_b):
            assert own_clients() >= 1
        assert own_clients() >= 1
    assert own_clients() == 0
