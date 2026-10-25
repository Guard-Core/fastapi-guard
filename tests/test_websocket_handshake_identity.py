import asyncio
import logging
from collections.abc import Generator
from typing import Any

import pytest
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient
from guard_core.core.checks.implementations import (
    emergency_mode as emergency_mode_module,
)
from guard_core.core.checks.implementations.emergency_mode import EmergencyModeCheck
from guard_core.handlers import ratelimit_handler as ratelimit_handler_module
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from starlette.websockets import WebSocketDisconnect

from guard import websocket as websocket_module
from guard.middleware import SecurityMiddleware
from guard.websocket import (
    WS_CLOSE_EMERGENCY_MODE,
    WS_CLOSE_REASONS,
    WS_CLOSE_SECURITY_CHECK_FAILED,
    WS_CLOSE_USER_AGENT_NOT_ALLOWED,
    guard_websocket,
    make_guard_websocket,
)

OUTSIDER = "203.0.113.50"
OPERATOR = "198.51.100.7"


@pytest.fixture(autouse=True)
def _reset_shared_state() -> Generator[None, None, None]:
    ratelimit_handler_module._by_ip_request_timestamps.clear()
    ratelimit_handler_module._by_ip_autoban_counts.clear()
    websocket_module._ws_detection_middlewares.clear()
    ip_ban_manager.banned_ips.clear()
    emergency_mode_module._emergency_samples.clear()
    yield
    websocket_module._ws_detection_middlewares.clear()
    ip_ban_manager.banned_ips.clear()


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "exclude_paths": [],
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


def _app(config: SecurityConfig) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")
        await websocket.close()

    return app


def _connect(
    app: FastAPI, headers: dict[str, str] | None = None, ip: str = OUTSIDER
) -> str:
    with TestClient(app, client=(ip, 12345)) as client:
        with client.websocket_connect("/ws", headers=dict(headers or {})) as websocket:
            text: str = websocket.receive_text()
            return text


def _refused(
    app: FastAPI, headers: dict[str, str] | None = None, ip: str = OUTSIDER
) -> WebSocketDisconnect:
    with TestClient(app, client=(ip, 12345)) as client:
        with pytest.raises(WebSocketDisconnect) as caught:
            with client.websocket_connect("/ws", headers=dict(headers or {})):
                pass
    return caught.value


def test_the_new_close_reasons_are_listed() -> None:
    assert WS_CLOSE_EMERGENCY_MODE in WS_CLOSE_REASONS
    assert WS_CLOSE_USER_AGENT_NOT_ALLOWED in WS_CLOSE_REASONS


def test_emergency_mode_closes_the_handshake_of_a_client_outside_the_whitelist() -> (
    None
):
    config = _config(emergency_mode=True, emergency_whitelist=[OPERATOR])

    refusal = _refused(_app(config))

    assert refusal.code == WS_CLOSE_EMERGENCY_MODE.code
    assert refusal.reason == WS_CLOSE_EMERGENCY_MODE.reason


def test_emergency_mode_admits_the_emergency_whitelist() -> None:
    config = _config(emergency_mode=True, emergency_whitelist=[OPERATOR])

    assert _connect(_app(config), ip=OPERATOR) == "connected"


def test_emergency_mode_covers_a_path_listed_in_exclude_paths() -> None:
    config = _config(
        emergency_mode=True, emergency_whitelist=[OPERATOR], exclude_paths=["/ws"]
    )

    assert _refused(_app(config)).code == WS_CLOSE_EMERGENCY_MODE.code


def test_an_emergency_exempt_path_stays_open() -> None:
    config = _config(
        emergency_mode=True,
        emergency_whitelist=[OPERATOR],
        emergency_exempt_paths=["/ws"],
    )

    assert _connect(_app(config)) == "connected"


def test_emergency_mode_in_passive_mode_logs_and_accepts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(
        emergency_mode=True, emergency_whitelist=[OPERATOR], passive_mode=True
    )

    with caplog.at_level(logging.WARNING):
        assert _connect(_app(config)) == "connected"

    assert any("[EMERGENCY MODE]" in record.message for record in caplog.records)


def test_a_dynamic_rule_turning_emergency_mode_on_applies_to_the_next_handshake() -> (
    None
):
    config = _config(emergency_whitelist=[OPERATOR])
    app = _app(config)

    assert _connect(app) == "connected"
    config.emergency_mode = True

    assert _refused(app).code == WS_CLOSE_EMERGENCY_MODE.code


def test_a_failing_emergency_check_closes_the_handshake_in_fail_secure_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def explode(self: EmergencyModeCheck, request: GuardRequest) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(EmergencyModeCheck, "check", explode)
    config = _config(emergency_mode=True, fail_secure=True)

    refusal = _refused(_app(config))

    assert refusal.code == WS_CLOSE_SECURITY_CHECK_FAILED.code
    assert refusal.reason == WS_CLOSE_SECURITY_CHECK_FAILED.reason


def test_a_blocked_user_agent_closes_the_handshake() -> None:
    config = _config(blocked_user_agents=["badbot"])

    refusal = _refused(_app(config), {"User-Agent": "badbot/1"})

    assert refusal.code == WS_CLOSE_USER_AGENT_NOT_ALLOWED.code
    assert refusal.reason == WS_CLOSE_USER_AGENT_NOT_ALLOWED.reason


def test_an_allowed_user_agent_is_accepted() -> None:
    config = _config(blocked_user_agents=["badbot"])

    assert _connect(_app(config), {"User-Agent": "goodbrowser/1"}) == "connected"


def test_an_empty_user_agent_closes_the_handshake_when_blocked() -> None:
    config = _config(block_empty_user_agent=True)

    assert _refused(_app(config), {"User-Agent": ""}).code == (
        WS_CLOSE_USER_AGENT_NOT_ALLOWED.code
    )


def test_a_whitelisted_client_skips_the_user_agent_check() -> None:
    config = _config(
        blocked_user_agents=["badbot"],
        whitelist=[OUTSIDER],
        whitelist_access_only=False,
    )

    assert _connect(_app(config), {"User-Agent": "badbot/1"}) == "connected"


def test_a_path_in_exclude_paths_skips_the_user_agent_check() -> None:
    config = _config(blocked_user_agents=["badbot"], exclude_paths=["/ws"])

    assert _connect(_app(config), {"User-Agent": "badbot/1"}) == "connected"


def test_a_blocked_user_agent_in_passive_mode_logs_and_accepts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(blocked_user_agents=["badbot"], passive_mode=True)

    with caplog.at_level(logging.WARNING):
        assert _connect(_app(config), {"User-Agent": "badbot/1"}) == "connected"

    assert any("Blocked user agent" in record.message for record in caplog.records)


def test_a_banned_client_in_passive_mode_logs_and_accepts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(passive_mode=True)
    asyncio.run(ip_ban_manager.ban_ip(OUTSIDER, duration=60, reason="test"))

    with caplog.at_level(logging.WARNING):
        assert _connect(_app(config)) == "connected"

    assert any(
        "[PASSIVE MODE]" in r.message and "Banned IP attempted access" in r.message
        for r in caplog.records
    )


def test_a_blacklisted_client_in_passive_mode_logs_and_accepts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(blacklist=[OUTSIDER], passive_mode=True)

    with caplog.at_level(logging.WARNING):
        assert _connect(_app(config)) == "connected"

    assert any(
        "[PASSIVE MODE]" in r.message and "IP not allowed" in r.message
        for r in caplog.records
    )


def test_a_blacklisted_client_without_passive_mode_is_closed() -> None:
    config = _config(blacklist=[OUTSIDER])

    refusal = _refused(_app(config))

    assert (refusal.code, refusal.reason) == (1008, "IP not allowed")


def test_an_exhausted_rate_limit_in_passive_mode_logs_and_accepts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(
        enable_rate_limiting=True, rate_limit=1, rate_limit_window=60, passive_mode=True
    )
    app = _app(config)

    with caplog.at_level(logging.WARNING):
        assert _connect(app) == "connected"
        assert _connect(app) == "connected"

    assert any(
        "[PASSIVE MODE]" in r.message and "Rate limit exceeded" in r.message
        for r in caplog.records
    )


def test_make_guard_websocket_applies_both_checks_without_middleware() -> None:
    config = _config(
        emergency_mode=True,
        emergency_whitelist=[OPERATOR],
        blocked_user_agents=["badbot"],
    )
    app = FastAPI()
    guard = make_guard_websocket(config)

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")
        await websocket.close()

    assert _refused(app).code == WS_CLOSE_EMERGENCY_MODE.code
    assert _connect(app, {"User-Agent": "goodbrowser/1"}, ip=OPERATOR) == "connected"
    assert (
        _refused(app, {"User-Agent": "badbot/1"}, ip=OPERATOR).code
        == WS_CLOSE_USER_AGENT_NOT_ALLOWED.code
    )
