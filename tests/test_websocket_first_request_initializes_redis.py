import logging
import os
import time
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest
import redis
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from starlette.websockets import WebSocketDisconnect

from guard._middleware_state import _STATE_REGISTRY
from guard.middleware import SecurityMiddleware
from guard.websocket import WS_CLOSE_EMERGENCY_MODE, guard_websocket
from tests.redis_isolation import suite_redis_prefix

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
UNREACHABLE_REDIS_URL = "redis://127.0.0.1:1/12"


def _app(config: SecurityConfig) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def index() -> dict[str, str]:
        return {"ok": "yes"}

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    return app


def _config(
    url: str, redis_fail_open: bool = False, passive_mode: bool = False
) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=url,
        redis_prefix=suite_redis_prefix(f"wp169{uuid.uuid4().hex[:8]}"),
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=100,
        rate_limit_window=60,
        redis_fail_open=redis_fail_open,
        passive_mode=passive_mode,
    )


def _wait_out_the_first_reconnect_window() -> None:
    """A manager that failed to connect tries again after a window that starts at
    0.25 s (LEDGER 6.644), so a Redis that is back is picked up within that."""
    time.sleep(0.3)


ClientFactory = Callable[[FastAPI], TestClient]


@pytest.fixture
def make_client() -> Iterator[ClientFactory]:
    """Clients that stay entered, so the app's Redis connections live in the
    portal's loop and are closed there before it stops."""
    clients: list[TestClient] = []

    def make(app: FastAPI) -> TestClient:
        client = TestClient(app, client=("127.0.0.1", 12345))
        client.__enter__()
        clients.append(client)
        return client

    yield make
    for client in clients:
        assert client.portal is not None
        for state in list(_STATE_REGISTRY.values()):
            redis_handler = state.handler_initializer.redis_handler
            if isinstance(redis_handler, RedisManager):
                client.portal.call(redis_handler.close)
        client.__exit__(None, None, None)


def _refusal(client: TestClient) -> WebSocketDisconnect:
    with pytest.raises(WebSocketDisconnect) as refused:
        with client.websocket_connect("/ws"):
            pass
    return refused.value


def test_websocket_as_first_request_writes_its_rate_key_to_redis(
    make_client: ClientFactory,
) -> None:
    config = _config(REDIS_URL)
    client = make_client(_app(config))
    with client.websocket_connect("/ws") as websocket:
        assert websocket.receive_text() == "connected"
    reader = redis.Redis.from_url(REDIS_URL)
    keys = list(reader.scan_iter(match=f"{config.redis_prefix}*"))
    try:
        assert keys, f"no key under {config.redis_prefix} in Redis"
    finally:
        for key in keys:
            reader.delete(key)
        reader.close()


def test_unreachable_redis_refuses_handshake_and_http_then_recovers(
    make_client: ClientFactory,
) -> None:
    config = _config(UNREACHABLE_REDIS_URL)
    client = make_client(_app(config))

    refusal = _refusal(client)
    assert refusal.code == WS_CLOSE_EMERGENCY_MODE.code == 1013
    assert client.get("/").status_code == 503

    config.redis_url = REDIS_URL
    _wait_out_the_first_reconnect_window()
    with client.websocket_connect("/ws") as websocket:
        assert websocket.receive_text() == "connected"
    reader = redis.Redis.from_url(REDIS_URL)
    for key in reader.scan_iter(match=f"{config.redis_prefix}*"):
        reader.delete(key)
    reader.close()


def test_unreachable_redis_with_fail_open_admits_handshake_and_http(
    make_client: ClientFactory,
) -> None:
    client = make_client(_app(_config(UNREACHABLE_REDIS_URL, redis_fail_open=True)))

    with client.websocket_connect("/ws") as websocket:
        assert websocket.receive_text() == "connected"
    assert client.get("/").status_code == 200


def test_passive_mode_logs_the_refusal_and_admits_the_handshake(
    caplog: pytest.LogCaptureFixture, make_client: ClientFactory
) -> None:
    client = make_client(_app(_config(UNREACHABLE_REDIS_URL, passive_mode=True)))

    with caplog.at_level(logging.INFO, logger="guard_core"):
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"
    assert any("[PASSIVE MODE]" in r.getMessage() for r in caplog.records)


def test_refused_cold_handshakes_construct_the_middleware_at_most_once(
    monkeypatch: pytest.MonkeyPatch, make_client: ClientFactory
) -> None:
    built: list[int] = []
    original = SecurityMiddleware.__init__

    def counting_init(self: SecurityMiddleware, *args: Any, **kwargs: Any) -> None:
        built.append(1)
        original(self, *args, **kwargs)

    config = _config(UNREACHABLE_REDIS_URL)
    client = make_client(_app(config))
    monkeypatch.setattr(SecurityMiddleware, "__init__", counting_init)

    _refusal(client)
    _refusal(client)
    config.redis_url = REDIS_URL
    _wait_out_the_first_reconnect_window()
    with client.websocket_connect("/ws") as websocket:
        assert websocket.receive_text() == "connected"

    assert len(built) <= 1
    reader = redis.Redis.from_url(REDIS_URL)
    for key in reader.scan_iter(match=f"{config.redis_prefix}*"):
        reader.delete(key)
    reader.close()
