"""D-188 end to end: a runtime Redis outage reaches the FastAPI client as 503
with Retry-After.

Real Starlette test client and the real engine. Only the Redis client the
engine holds is replaced, by one whose commands raise redis' own
ConnectionError. The WebSocket path has its own tests.
"""

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.models import SecurityConfig
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from guard.middleware import SecurityMiddleware
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL


class _DeadRedis(Redis):
    async def execute_command(self, *args: Any, **options: Any) -> Any:
        raise RedisConnectionError("Redis went away")


def _security_middleware_of(app: FastAPI) -> SecurityMiddleware:
    layer: Any = app.middleware_stack
    while not isinstance(layer, SecurityMiddleware):
        layer = layer.app
    return layer


def _status_and_retry_after_after_redis_died(
    path: str, **overrides: Any
) -> tuple[int, str | None]:
    settings: dict[str, Any] = {
        "enable_redis": True,
        "redis_url": REDIS_URL,
        "redis_prefix": f"{REDIS_PREFIX}wp192:",
        "enable_agent": False,
        "fail_secure": True,
        "redis_fail_open": False,
        "enable_penetration_detection": False,
        "exclude_paths": ["/health"],
    }
    settings.update(overrides)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=SecurityConfig(**settings))

    @app.get("/open")
    async def open_() -> dict[str, str]:
        return {"message": "ok"}

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"message": "ok"}

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        assert client.get("/open").status_code == 200
        middleware = _security_middleware_of(app)
        assert middleware.redis_handler is not None
        middleware.redis_handler._redis = _DeadRedis()
        response = client.get(path)
    return response.status_code, response.headers.get("Retry-After")


@pytest.mark.parametrize("path", ["/open", "/health"])
def test_runtime_outage_answers_503_with_retry_after(path: str) -> None:
    status, retry_after = _status_and_retry_after_after_redis_died(path)
    assert status == 503
    assert retry_after == "5"


@pytest.mark.parametrize("path", ["/open", "/health"])
def test_passive_mode_admits_during_a_runtime_outage(path: str) -> None:
    status, _ = _status_and_retry_after_after_redis_died(path, passive_mode=True)
    assert status == 200


@pytest.mark.parametrize("path", ["/open", "/health"])
def test_redis_fail_open_admits_during_a_runtime_outage(path: str) -> None:
    status, _ = _status_and_retry_after_after_redis_died(path, redis_fail_open=True)
    assert status == 200
