import logging
from collections.abc import Generator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.models import SecurityConfig

from guard import middleware as middleware_module
from guard.asgi import PureASGISecurityMiddleware

DEAD_REDIS_URL = "redis://127.0.0.1:6399"
INIT_OUTAGE_LINE = "Redis unavailable during initialization"


@pytest.fixture(autouse=True)
def _reset_outage_state() -> Generator[None, None, None]:
    middleware_module._init_outage_samples.clear()
    yield
    middleware_module._init_outage_samples.clear()


def _app(config: SecurityConfig) -> FastAPI:
    app = FastAPI()
    app.add_middleware(PureASGISecurityMiddleware, config=config)

    @app.post("/echo")
    async def echo(payload: dict[str, str]) -> dict[str, str]:
        return payload

    return app


def test_passive_cold_start_with_redis_down_admits_and_logs_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(redis_url=DEAD_REDIS_URL, passive_mode=True)

    with caplog.at_level(logging.ERROR):
        with TestClient(_app(config), client=("127.0.0.1", 12345)) as client:
            responses = [client.post("/echo", json={"a": "b"}) for _ in range(3)]

    assert [(r.status_code, r.json()) for r in responses] == [(200, {"a": "b"})] * 3
    assert "Retry-After" not in responses[0].headers
    lines = [
        r
        for r in caplog.records
        if INIT_OUTAGE_LINE in r.getMessage() and "passive_mode" in r.getMessage()
    ]
    assert len(lines) == 1


def test_not_passive_cold_start_with_redis_down_keeps_503_with_retry_after() -> None:
    config = SecurityConfig(redis_url=DEAD_REDIS_URL)

    with TestClient(_app(config), client=("127.0.0.1", 12345)) as client:
        response = client.post("/echo", json={"a": "b"})

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"
