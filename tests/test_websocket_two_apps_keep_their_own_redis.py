import asyncio
import os
import uuid
from typing import Any

from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig

from guard.lifespan import _find_security_redis_handler
from guard.middleware import SecurityMiddleware
from guard.websocket import guard_websocket
from tests.redis_isolation import suite_redis_prefix

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")


def _app(config: SecurityConfig) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    return app


def _config(prefix: str) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=100,
        rate_limit_window=60,
    )


def test_each_apps_websocket_checks_use_that_apps_redis_handler() -> None:
    tag = uuid.uuid4().hex[:8]
    config_a = _config(suite_redis_prefix(f"wsa{tag}"))
    config_b = _config(suite_redis_prefix(f"wsb{tag}"))
    app_a, app_b = _app(config_a), _app(config_b)
    found: dict[str, Any] = {}

    with (
        TestClient(app_a, client=("127.0.0.1", 12345)) as client_a,
        TestClient(app_b, client=("127.0.0.1", 12345)) as client_b,
    ):
        for client, config in ((client_a, config_a), (client_b, config_b)):
            assert client.portal is not None
            client.portal.call(RedisManager(config).initialize)
        last_built = RedisManager._instance
        assert last_built is not None
        assert last_built.config is config_b

        for name, client, app in (
            ("a", client_a, app_a),
            ("b", client_b, app_b),
        ):
            with client.websocket_connect("/ws") as websocket:
                assert websocket.receive_text() == "connected"
            assert client.portal is not None
            found[name] = client.portal.call(_find_security_redis_handler, app)

        for client, config in ((client_a, config_a), (client_b, config_b)):
            assert client.portal is not None
            client.portal.call(RedisManager(config).close)

    assert found["a"] is not None
    assert found["a"].config is config_a
    assert found["b"] is not None
    assert found["b"].config is config_b


def test_a_second_live_loop_with_no_client_of_its_own_finds_no_handler() -> None:
    config = _config(suite_redis_prefix(f"wsl{uuid.uuid4().hex[:8]}"))
    app = _app(config)

    async def look() -> Any:
        return _find_security_redis_handler(app)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        assert client.portal is not None
        client.portal.call(RedisManager(config).initialize)
        on_the_apps_loop = client.portal.call(look)
        on_another_loop = asyncio.run(look())

    assert on_the_apps_loop is not None
    assert on_another_loop is None
