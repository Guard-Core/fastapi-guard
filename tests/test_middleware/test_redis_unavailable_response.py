import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig

from guard.lifespan import guard_lifespan
from guard.middleware import SecurityMiddleware
from tests.redis_isolation import REDIS_URL

DEAD_REDIS_URL = "redis://127.0.0.1:6399"


def _app_with_dead_redis() -> FastAPI:
    config = SecurityConfig(redis_url=DEAD_REDIS_URL)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def root() -> dict[str, bool]:
        return {"ok": True}

    return app


def test_requests_get_503_with_retry_after_while_redis_is_unreachable() -> None:
    app = _app_with_dead_redis()

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        for _ in range(3):
            response = client.get("/")
            assert response.status_code == 503
            assert response.headers["Retry-After"] == "5"


def test_next_request_succeeds_once_redis_initialization_recovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app_with_dead_redis()

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        first = client.get("/")
        assert first.status_code == 503

        real_initialize = RedisManager.initialize

        async def _fake_initialize(self: RedisManager) -> None:
            self.config.redis_url = REDIS_URL
            await real_initialize(self)

        monkeypatch.setattr(RedisManager, "initialize", _fake_initialize)

        second = client.get("/")
        assert second.status_code == 200

        assert client.portal is not None
        client.portal.call(RedisManager(SecurityConfig()).close)


def test_lifespan_warmer_logs_and_continues_when_redis_is_unreachable_at_startup() -> (
    None
):
    config = SecurityConfig(redis_url=DEAD_REDIS_URL)
    app = FastAPI(lifespan=guard_lifespan)
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def root() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        response = client.get("/")
        assert response.status_code == 503
        assert response.headers["Retry-After"] == "5"
