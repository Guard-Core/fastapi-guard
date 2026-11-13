"""The websocket handshake runs the engine checks that can apply to a socket (the
rest are listed with their reason in the websocket guide): HTTPS enforcement,
request logging, cloud provider, the route rules of a decorated endpoint (required
headers, authentication, referrer, custom validators, time window) and the custom
request check. Membership, not configuration, decides `is_whitelisted`."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient
from guard_core.core.checks.implementations.cloud_ip_refresh import CloudIpRefreshCheck
from guard_core.core.checks.implementations.cloud_provider import CloudProviderCheck
from guard_core.handlers import ratelimit_handler as ratelimit_handler_module
from guard_core.models import SecurityConfig
from starlette.responses import Response
from starlette.websockets import WebSocketDisconnect

from guard import SecurityDecorator, websocket as websocket_module
from guard.middleware import SecurityMiddleware
from guard.websocket import guard_websocket


@pytest.fixture(autouse=True)
def _fresh_state() -> None:
    ratelimit_handler_module._by_ip_request_timestamps.clear()
    ratelimit_handler_module._by_ip_autoban_counts.clear()
    websocket_module._ws_detection_middlewares.clear()


def _config(**overrides: Any) -> SecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "ban_on_hostile_signals": False,
    }
    settings.update(overrides)
    return SecurityConfig(**settings)


def _app(config: SecurityConfig, *decorators: Any) -> FastAPI:
    app = FastAPI()
    guard = SecurityDecorator(config)
    app.state.guard_decorator = guard
    app.add_middleware(SecurityMiddleware, config=config)

    async def endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()
        await websocket.send_text(str(websocket.state.is_whitelisted))
        await websocket.close()

    for decorate in decorators:
        endpoint = decorate(guard)(endpoint)
    app.websocket("/ws")(endpoint)
    return app


def _outcome(
    app: FastAPI, headers: dict[str, str] | None = None, base: str = "http://testserver"
) -> str:
    with TestClient(app, base_url=base, client=("127.0.0.1", 40000)) as client:
        try:
            with client.websocket_connect("/ws", headers=headers or {}) as socket:
                return "open:" + socket.receive_text()
        except WebSocketDisconnect as closed:
            return f"closed:{closed.code}:{closed.reason}"


def test_enforce_https_refuses_ws_and_admits_wss() -> None:
    app = _app(
        _config(
            enforce_https=True,
            trust_x_forwarded_proto=True,
            trusted_proxies=["127.0.0.1"],
        )
    )

    assert _outcome(app) == "closed:1008:HTTPS required"
    assert _outcome(app, {"X-Forwarded-Proto": "https"}).startswith("open:")


def test_a_required_header_of_the_endpoint_is_enforced() -> None:
    app = _app(_config(), lambda g: g.require_headers({"x-need": "1"}))

    assert _outcome(app) == "closed:1008:Required header missing"
    assert _outcome(app, {"x-need": "1"}).startswith("open:")


def test_the_authorization_header_rule_of_the_endpoint_is_enforced() -> None:
    app = _app(_config(), lambda g: g.require_authorization_header("bearer"))

    assert _outcome(app) == "closed:1008:Authentication required"
    assert _outcome(app, {"Authorization": "Bearer abc"}).startswith("open:")


def test_the_referrer_rule_of_the_endpoint_is_enforced() -> None:
    app = _app(_config(), lambda g: g.require_referrer(["good.example"]))

    assert _outcome(app) == "closed:1008:Referrer not allowed"
    assert _outcome(app, {"Referer": "https://good.example/x"}).startswith("open:")


def test_a_custom_validator_of_the_endpoint_runs() -> None:
    async def refuse(request: Any) -> Response:
        return Response("no", status_code=403)

    app = _app(_config(), lambda g: g.custom_validation(refuse))

    assert _outcome(app) == "closed:1008:Request validation failed"


def test_the_time_window_of_the_endpoint_is_enforced() -> None:
    later = datetime.now(timezone.utc) + timedelta(hours=2)
    start, end = later.strftime("%H:%M"), (later + timedelta(hours=1)).strftime("%H:%M")
    app = _app(_config(), lambda g: g.time_window(start, end))

    assert _outcome(app) == "closed:1008:Access outside the allowed time window"


def test_the_custom_request_check_runs() -> None:
    async def refuse(request: Any) -> Response:
        return Response("no", status_code=403)

    app = _app(_config(custom_request_check=refuse))

    assert _outcome(app) == "closed:1008:Request refused"


def test_a_cloud_provider_refusal_closes_the_handshake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def nothing_to_refresh(self: Any, request: Any) -> None:
        return None

    async def refuse(self: Any, request: Any) -> Response:
        return Response("no", status_code=403)

    monkeypatch.setattr(CloudIpRefreshCheck, "check", nothing_to_refresh)
    monkeypatch.setattr(CloudProviderCheck, "check", refuse)
    app = _app(_config(block_cloud_providers={"AWS"}))

    assert _outcome(app) == "closed:1008:Cloud provider IP not allowed"


def test_the_handshake_is_logged_like_a_request(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app(_config(log_request_level="INFO"))

    with caplog.at_level(logging.INFO):
        _outcome(app)

    assert any("/ws" in record.getMessage() for record in caplog.records)


def test_a_client_off_the_whitelist_is_not_marked_whitelisted_under_passive_mode() -> (
    None
):
    app = _app(
        _config(whitelist=("10.9.9.9",), whitelist_access_only=False, passive_mode=True)
    )

    assert _outcome(app) == "open:False"


def test_a_client_on_the_whitelist_is_marked_whitelisted() -> None:
    app = _app(_config(whitelist=("127.0.0.1",), whitelist_access_only=False))

    assert _outcome(app) == "open:True"
