import logging
from collections.abc import Generator

import pytest
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient
from guard_core.exceptions import GuardRedisError
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.models import SecurityConfig
from starlette.websockets import WebSocketDisconnect

from guard import middleware as middleware_module, websocket as websocket_module
from guard.middleware import SecurityMiddleware
from guard.websocket import WS_CLOSE_SECURITY_CHECK_FAILED, guard_websocket

DEAD_REDIS_URL = "redis://127.0.0.1:6399"
INIT_OUTAGE_LINE = "Redis unavailable during initialization"


@pytest.fixture(autouse=True)
def _reset_outage_state() -> Generator[None, None, None]:
    middleware_module._init_outage_samples.clear()
    websocket_module._ws_detection_middlewares.clear()
    yield
    middleware_module._init_outage_samples.clear()
    websocket_module._ws_detection_middlewares.clear()


def _app(config: SecurityConfig) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def root() -> dict[str, bool]:
        return {"ok": True}

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")
        await websocket.close()

    return app


def test_passive_cold_start_with_redis_down_admits_http_and_logs_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(redis_url=DEAD_REDIS_URL, passive_mode=True)

    with caplog.at_level(logging.ERROR):
        with TestClient(_app(config), client=("127.0.0.1", 12345)) as client:
            responses = [client.get("/") for _ in range(3)]

    assert [r.status_code for r in responses] == [200, 200, 200]
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
        response = client.get("/")

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"


async def _raise_redis_error(ip: str) -> bool:
    raise GuardRedisError(503, "Redis operation failed")


def _warm_outage_config(passive_mode: bool) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        redis_fail_open=False,
        fail_secure=True,
        passive_mode=passive_mode,
    )


def test_passive_warm_outage_admits_the_websocket_and_logs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(ip_ban_manager, "is_ip_banned", _raise_redis_error)

    with caplog.at_level(logging.WARNING):
        with TestClient(
            _app(_warm_outage_config(passive_mode=True)), client=("127.0.0.1", 12345)
        ) as client:
            with client.websocket_connect("/ws") as websocket:
                assert websocket.receive_text() == "connected"

    assert any(
        "ip_ban_manager.is_ip_banned" in r.getMessage()
        and "passive_mode" in r.getMessage()
        for r in caplog.records
    )


def test_not_passive_warm_outage_keeps_close_1013(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ip_ban_manager, "is_ip_banned", _raise_redis_error)

    with TestClient(
        _app(_warm_outage_config(passive_mode=False)), client=("127.0.0.1", 12345)
    ) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == WS_CLOSE_SECURITY_CHECK_FAILED.code
