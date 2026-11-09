import logging
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.models import SecurityConfig

from guard.lifespan import guard_lifespan
from guard.middleware import SecurityMiddleware

WARNING_SUBSTRING = "lazy_init=False was set"


def _app_with_health_route(config: SecurityConfig, **fastapi_kwargs: Any) -> FastAPI:
    app = FastAPI(**fastapi_kwargs)
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    return app


def test_warns_when_lazy_init_false_and_no_lifespan_runs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(enable_redis=False, lazy_init=False)
    app = _app_with_health_route(config)

    with caplog.at_level(logging.WARNING):
        TestClient(app, client=("127.0.0.1", 12345)).get("/health")

    assert any(WARNING_SUBSTRING in r.message for r in caplog.records)


def test_no_warning_when_the_lifespan_runs_without_a_guard_hook(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(enable_redis=False, lazy_init=False)
    app = _app_with_health_route(config)

    with caplog.at_level(logging.WARNING):
        with TestClient(app, client=("127.0.0.1", 12345)) as client:
            client.get("/health")

    assert not any(WARNING_SUBSTRING in r.message for r in caplog.records)


def test_no_warning_when_lazy_init_true(caplog: pytest.LogCaptureFixture) -> None:
    config = SecurityConfig(enable_redis=False, lazy_init=True)
    app = _app_with_health_route(config)

    with caplog.at_level(logging.WARNING):
        with TestClient(app, client=("127.0.0.1", 12345)) as client:
            client.get("/health")

    assert not any(WARNING_SUBSTRING in r.message for r in caplog.records)


def test_no_warning_when_lifespan_wired(caplog: pytest.LogCaptureFixture) -> None:
    config = SecurityConfig(enable_redis=False, lazy_init=False)
    app = _app_with_health_route(config, lifespan=guard_lifespan)

    with caplog.at_level(logging.WARNING):
        with TestClient(app, client=("127.0.0.1", 12345)) as client:
            client.get("/health")

    assert not any(WARNING_SUBSTRING in r.message for r in caplog.records)
