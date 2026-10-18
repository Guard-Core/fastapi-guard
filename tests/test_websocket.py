import asyncio
import logging
from collections.abc import Generator, MutableMapping
from typing import Any

import pytest
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient
from guard_core import check_rate_limit_by_ip as real_check_rate_limit_by_ip
from guard_core.core.events import SecurityEventBus
from guard_core.exceptions import GuardRedisError
from guard_core.handlers import ratelimit_handler as ratelimit_handler_module
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from starlette.exceptions import WebSocketException
from starlette.websockets import WebSocketDisconnect

from guard import websocket as websocket_module
from guard.middleware import SecurityMiddleware
from guard.websocket import (
    WS_CLOSE_IP_BANNED,
    WS_CLOSE_REASONS,
    WS_CLOSE_SECURITY_CHECK_FAILED,
    WS_CLOSE_SUSPICIOUS_ACTIVITY,
    WebSocketCloseReason,
    _WebSocketDetectionMiddleware,
    _WebSocketGuardRequest,
    guard_websocket,
    make_guard_websocket,
)


@pytest.fixture(autouse=True)
def _reset_by_ip_rate_limit_state() -> None:
    ratelimit_handler_module._by_ip_request_timestamps.clear()
    ratelimit_handler_module._by_ip_autoban_counts.clear()


@pytest.fixture(autouse=True)
def _reset_ws_detection_middleware_cache() -> Generator[None, None, None]:
    websocket_module._ws_detection_middlewares.clear()
    yield
    websocket_module._ws_detection_middlewares.clear()


@pytest.fixture
def captured_events(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    original = SecurityEventBus.send_middleware_event

    async def _capture(self: SecurityEventBus, *args: Any, **kwargs: Any) -> None:
        events.append(kwargs)
        await original(self, *args, **kwargs)

    monkeypatch.setattr(SecurityEventBus, "send_middleware_event", _capture)
    return events


def _app_with_websocket(config: SecurityConfig) -> FastAPI:
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


def _client_less_websocket(app: FastAPI) -> WebSocket:
    async def receive() -> dict[str, Any]:
        raise NotImplementedError

    async def send(message: MutableMapping[str, Any]) -> None:
        raise NotImplementedError

    scope = {
        "type": "websocket",
        "path": "/ws",
        "headers": [],
        "query_string": b"",
        "app": app,
    }
    return WebSocket(scope, receive=receive, send=send)


def test_guard_websocket_rejects_banned_ip_before_accept() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    app = _app_with_websocket(config)
    asyncio.run(ip_ban_manager.ban_ip("203.0.113.50", duration=60, reason="test"))

    with TestClient(app, client=("203.0.113.50", 12345)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "IP banned"


def test_guard_websocket_accepts_allowed_ip() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"


def test_guard_websocket_rejects_once_rate_limit_exhausted() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "Rate limit exceeded"


def test_guard_websocket_honours_forwarded_header_behind_trusted_proxy() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        trusted_proxies=("10.0.0.1",),
        blacklist=("203.0.113.9",),
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("10.0.0.1", 5000)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect(
                "/ws", headers={"X-Forwarded-For": "203.0.113.9"}
            ):
                pass

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "IP not allowed"


def test_guard_websocket_requires_security_middleware_registered() -> None:
    app = FastAPI()

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with pytest.raises(RuntimeError):
            with client.websocket_connect("/ws"):
                pass


async def test_guard_websocket_rejects_client_less_socket_by_default() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    app = _app_with_websocket(config)
    websocket = _client_less_websocket(app)

    with pytest.raises(WebSocketException) as exc_info:
        await guard_websocket(websocket)

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "Client address could not be determined"


async def test_guard_websocket_allows_client_less_socket_when_not_fail_secure() -> None:
    config = SecurityConfig(
        enable_redis=False, enable_penetration_detection=False, fail_secure=False
    )
    app = _app_with_websocket(config)
    websocket = _client_less_websocket(app)

    await guard_websocket(websocket)


async def test_websocket_guard_request_exposes_the_full_protocol_surface() -> None:
    async def receive() -> dict[str, Any]:
        raise NotImplementedError

    async def send(message: MutableMapping[str, Any]) -> None:
        raise NotImplementedError

    scope = {
        "type": "websocket",
        "path": "/ws",
        "headers": [(b"host", b"testserver")],
        "query_string": b"token=abc",
        "scheme": "ws",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
        "app": FastAPI(),
    }
    websocket = WebSocket(scope, receive=receive, send=send)
    guard_request = _WebSocketGuardRequest(websocket)

    assert guard_request.url_path == "/ws"
    assert guard_request.url_scheme == "ws"
    assert guard_request.url_full == "ws://testserver/ws?token=abc"
    assert guard_request.url_replace_scheme("wss").startswith("wss://")
    assert guard_request.method == "WEBSOCKET"
    assert guard_request.client_host == "127.0.0.1"
    assert guard_request.query_params["token"] == "abc"
    assert await guard_request.body() == b""
    assert guard_request.scope is scope


async def test_websocket_guard_request_url_path_strips_root_path() -> None:
    async def receive() -> dict[str, Any]:
        raise NotImplementedError

    async def send(message: MutableMapping[str, Any]) -> None:
        raise NotImplementedError

    scope = {
        "type": "websocket",
        "path": "/mounted/ws",
        "headers": [(b"host", b"testserver")],
        "query_string": b"",
        "scheme": "ws",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
        "root_path": "/mounted",
        "app": FastAPI(),
    }
    websocket = WebSocket(scope, receive=receive, send=send)
    guard_request = _WebSocketGuardRequest(websocket)

    assert guard_request.url_path == "/ws"


async def _raise_ip_ban_redis_error(ip: str) -> bool:
    raise GuardRedisError(503, "Redis operation failed")


async def _raise_rate_limit_redis_error(*args: Any, **kwargs: Any) -> bool:
    raise GuardRedisError(503, "Redis operation failed")


def test_guard_websocket_skips_ip_ban_check_when_redis_fail_open(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(ip_ban_manager, "is_ip_banned", _raise_ip_ban_redis_error)
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        redis_fail_open=True,
    )
    app = _app_with_websocket(config)

    with caplog.at_level(logging.WARNING):
        with TestClient(app, client=("127.0.0.1", 12345)) as client:
            with client.websocket_connect("/ws") as websocket:
                assert websocket.receive_text() == "connected"

    assert any(
        "ip_ban_manager.is_ip_banned" in r.message and "failing open" in r.message
        for r in caplog.records
    )


def test_guard_websocket_closes_with_1013_when_ip_ban_check_fails_secure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ip_ban_manager, "is_ip_banned", _raise_ip_ban_redis_error)
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        redis_fail_open=False,
        fail_secure=True,
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1013
    assert exc_info.value.reason == "Security check failed"


def test_guard_websocket_skips_ip_ban_check_when_not_fail_secure(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(ip_ban_manager, "is_ip_banned", _raise_ip_ban_redis_error)
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        redis_fail_open=False,
        fail_secure=False,
    )
    app = _app_with_websocket(config)

    with caplog.at_level(logging.ERROR):
        with TestClient(app, client=("127.0.0.1", 12345)) as client:
            with client.websocket_connect("/ws") as websocket:
                assert websocket.receive_text() == "connected"

    assert any("ip_ban_manager.is_ip_banned" in r.message for r in caplog.records)


def test_guard_websocket_closes_with_1013_when_rate_limit_check_fails_secure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "guard.websocket.check_rate_limit_by_ip", _raise_rate_limit_redis_error
    )
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        redis_fail_open=False,
        fail_secure=True,
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1013
    assert exc_info.value.reason == "Security check failed"


def test_ws_close_reasons_pins_the_exact_code_reason_pair_set() -> None:
    assert set(WS_CLOSE_REASONS) == {
        WebSocketCloseReason(1008, "IP banned"),
        WebSocketCloseReason(1008, "IP not allowed"),
        WebSocketCloseReason(1008, "Rate limit exceeded"),
        WebSocketCloseReason(1008, "Client address could not be determined"),
        WebSocketCloseReason(1013, "Security check failed"),
        WebSocketCloseReason(1008, "Suspicious activity detected"),
    }
    assert len(WS_CLOSE_REASONS) == 6


def test_guard_websocket_skips_rate_limit_when_client_is_whitelisted() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        whitelist=("127.0.0.1",),
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        for _ in range(3):
            with client.websocket_connect("/ws") as websocket:
                assert websocket.receive_text() == "connected"


requires_whitelist_access_only = pytest.mark.skipif(
    "whitelist_access_only" not in SecurityConfig.model_fields,
    reason="the installed guard-core predates whitelist_access_only",
)


@requires_whitelist_access_only
def test_ws_rate_limits_a_whitelisted_client_under_access_only_whitelist() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        whitelist=("127.0.0.1",),
        whitelist_access_only=True,
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 12346)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "Rate limit exceeded"


@requires_whitelist_access_only
def test_ws_skips_the_rate_limit_of_a_whitelisted_client_with_the_flag_off() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        whitelist=("127.0.0.1",),
        whitelist_access_only=False,
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 12347)) as client:
        for _ in range(3):
            with client.websocket_connect("/ws") as websocket:
                assert websocket.receive_text() == "connected"


@requires_whitelist_access_only
def test_guard_websocket_marks_the_connection_by_the_flag() -> None:
    marked: dict[str, bool] = {}

    def _record(access_only: bool) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            enable_rate_limiting=False,
            whitelist=("127.0.0.1",),
            whitelist_access_only=access_only,
        )
        app = FastAPI()

        @app.websocket("/ws")
        async def endpoint(
            websocket: WebSocket, _: None = Depends(make_guard_websocket(config))
        ) -> None:
            await websocket.accept()
            await websocket.send_text(str(websocket.state.is_whitelisted))

        with TestClient(app, client=("127.0.0.1", 12348)) as client:
            with client.websocket_connect("/ws") as websocket:
                marked[str(access_only)] = websocket.receive_text() == "True"

    _record(False)
    _record(True)

    assert marked == {"False": True, "True": False}


def _app_with_factory_websocket(config: SecurityConfig) -> FastAPI:
    app = FastAPI()

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(make_guard_websocket(config))
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    return app


def test_make_guard_websocket_enforces_ban_list_without_middleware() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    app = _app_with_factory_websocket(config)
    asyncio.run(ip_ban_manager.ban_ip("203.0.113.61", duration=60, reason="test"))

    with TestClient(app, client=("203.0.113.61", 12345)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "IP banned"


def test_make_guard_websocket_enforces_allow_list_without_middleware() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        blacklist=("203.0.113.62",),
    )
    app = _app_with_factory_websocket(config)

    with TestClient(app, client=("203.0.113.62", 12345)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "IP not allowed"


def test_make_guard_websocket_enforces_rate_limit_without_middleware() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
    )
    app = _app_with_factory_websocket(config)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "Rate limit exceeded"


def test_guard_websocket_still_raises_without_middleware_beside_factory_route() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    app = FastAPI()

    @app.websocket("/factory")
    async def factory_endpoint(
        websocket: WebSocket, _: None = Depends(make_guard_websocket(config))
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    @app.websocket("/legacy")
    async def legacy_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/factory") as websocket:
            assert websocket.receive_text() == "connected"

        with pytest.raises(RuntimeError):
            with client.websocket_connect("/legacy"):
                pass


def test_guard_websocket_sets_client_ip_on_state_for_direct_peer() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)
    captured: dict[str, str] = {}

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()
        captured["client_ip"] = websocket.state.client_ip
        await websocket.send_text("connected")

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"

    assert captured["client_ip"] == "127.0.0.1"


def test_guard_websocket_sets_client_ip_on_state_for_trusted_proxy_chain() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        trusted_proxies=("10.0.0.1",),
    )
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)
    captured: dict[str, str] = {}

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()
        captured["client_ip"] = websocket.state.client_ip
        await websocket.send_text("connected")

    with TestClient(app, client=("10.0.0.1", 5000)) as client:
        with client.websocket_connect(
            "/ws", headers={"X-Forwarded-For": "203.0.113.9"}
        ) as websocket:
            assert websocket.receive_text() == "connected"

    assert captured["client_ip"] == "203.0.113.9"


async def test_guard_websocket_falls_back_to_memory_when_manager_not_initialized() -> (
    None
):
    RedisManager._instance = None
    config = SecurityConfig(
        enable_redis=True,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "Rate limit exceeded"
    final_instance: RedisManager | None = RedisManager._instance
    assert final_instance is not None
    assert final_instance._redis is None


async def test_guard_websocket_reuses_the_middlewares_redis_manager(
    security_config_redis: SecurityConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    security_config_redis.enable_redis = True
    security_config_redis.enable_penetration_detection = False
    security_config_redis.enable_rate_limiting = True
    security_config_redis.rate_limit = 1
    security_config_redis.rate_limit_window = 60
    security_config_redis.whitelist = ()
    security_config_redis.blocked_countries = frozenset()
    config = security_config_redis

    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    captured: dict[str, Any] = {}

    async def _capturing_check_rate_limit_by_ip(*args: Any, **kwargs: Any) -> bool:
        captured["redis_handler"] = kwargs.get("redis_handler")
        return await real_check_rate_limit_by_ip(*args, **kwargs)

    monkeypatch.setattr(
        "guard.websocket.check_rate_limit_by_ip", _capturing_check_rate_limit_by_ip
    )

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        assert client.portal is not None
        client.portal.call(RedisManager(config).initialize)

        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

        assert client.portal is not None
        client.portal.call(RedisManager(config).close)

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "Rate limit exceeded"
    assert captured["redis_handler"] is not None
    assert captured["redis_handler"] is RedisManager._instance


async def test_make_guard_websocket_warns_once_and_falls_back_to_memory_store(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        enable_redis=True,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
    )

    with caplog.at_level(logging.WARNING):
        dependency = make_guard_websocket(config)

    warnings = [
        r
        for r in caplog.records
        if "make_guard_websocket" in r.message and "in-memory store" in r.message
    ]
    assert len(warnings) == 1

    app = FastAPI()

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(dependency)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "Rate limit exceeded"

    warnings_after_connects = [
        r
        for r in caplog.records
        if "make_guard_websocket" in r.message and "in-memory store" in r.message
    ]
    assert len(warnings_after_connects) == 1


async def test_make_guard_websocket_uses_the_given_redis_handler(
    security_config_redis: SecurityConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    security_config_redis.enable_redis = True
    security_config_redis.enable_penetration_detection = False
    security_config_redis.enable_rate_limiting = True
    security_config_redis.rate_limit = 1
    security_config_redis.rate_limit_window = 60
    security_config_redis.whitelist = ()
    security_config_redis.blocked_countries = frozenset()
    config = security_config_redis

    redis_handler = RedisManager(config)

    captured: dict[str, Any] = {}

    async def _capturing_check_rate_limit_by_ip(*args: Any, **kwargs: Any) -> bool:
        captured["redis_handler"] = kwargs.get("redis_handler")
        return await real_check_rate_limit_by_ip(*args, **kwargs)

    monkeypatch.setattr(
        "guard.websocket.check_rate_limit_by_ip", _capturing_check_rate_limit_by_ip
    )

    dependency = make_guard_websocket(config, redis_handler=redis_handler)
    app = FastAPI()

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(dependency)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        assert client.portal is not None
        client.portal.call(redis_handler.initialize)

        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

        client.portal.call(redis_handler.close)

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "Rate limit exceeded"
    assert captured["redis_handler"] is redis_handler


async def test_make_guard_websocket_never_mutates_the_redis_singletons_config(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.enable_redis = True
    owner_config = security_config_redis
    owner_manager = RedisManager(owner_config)
    await owner_manager.initialize()

    foreign_config = SecurityConfig(
        enable_redis=True,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
    )
    dependency = make_guard_websocket(foreign_config)
    app = FastAPI()

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(dependency)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"

    assert RedisManager._instance is owner_manager
    assert RedisManager._instance.config is owner_config
    await owner_manager.close()


def test_guard_websocket_rejects_script_tag_in_query_param_when_active() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 20001)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws?q=<script>alert(1)</script>"):
                pass

    assert exc_info.value.code == WS_CLOSE_SUSPICIOUS_ACTIVITY.code
    assert exc_info.value.reason == WS_CLOSE_SUSPICIOUS_ACTIVITY.reason


def test_guard_websocket_rejects_script_tag_in_header_when_active() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 20002)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect(
                "/ws", headers={"X-Evil": "<script>alert(1)</script>"}
            ):
                pass

    assert exc_info.value.code == WS_CLOSE_SUSPICIOUS_ACTIVITY.code
    assert exc_info.value.reason == WS_CLOSE_SUSPICIOUS_ACTIVITY.reason


def test_guard_websocket_rejects_script_tag_in_cookie_when_active() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 20003)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect(
                "/ws", headers={"Cookie": "session=abc; x=<script>alert(1)</script>"}
            ):
                pass

    assert exc_info.value.code == WS_CLOSE_SUSPICIOUS_ACTIVITY.code
    assert exc_info.value.reason == WS_CLOSE_SUSPICIOUS_ACTIVITY.reason


def test_guard_websocket_logs_and_accepts_script_tag_in_query_param_when_passive(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        enable_redis=False, enable_penetration_detection=True, passive_mode=True
    )
    app = _app_with_websocket(config)

    with caplog.at_level(logging.WARNING):
        with TestClient(app, client=("127.0.0.1", 20004)) as client:
            with client.websocket_connect(
                "/ws?q=<script>alert(1)</script>"
            ) as websocket:
                assert websocket.receive_text() == "connected"

    assert any("[PASSIVE MODE]" in r.message for r in caplog.records)


def test_guard_websocket_logs_and_accepts_script_tag_in_header_when_passive(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        enable_redis=False, enable_penetration_detection=True, passive_mode=True
    )
    app = _app_with_websocket(config)

    with caplog.at_level(logging.WARNING):
        with TestClient(app, client=("127.0.0.1", 20005)) as client:
            with client.websocket_connect(
                "/ws", headers={"X-Evil": "<script>alert(1)</script>"}
            ) as websocket:
                assert websocket.receive_text() == "connected"

    assert any("[PASSIVE MODE]" in r.message for r in caplog.records)


def test_guard_websocket_logs_and_accepts_script_tag_in_cookie_when_passive(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        enable_redis=False, enable_penetration_detection=True, passive_mode=True
    )
    app = _app_with_websocket(config)

    with caplog.at_level(logging.WARNING):
        with TestClient(app, client=("127.0.0.1", 20006)) as client:
            with client.websocket_connect(
                "/ws", headers={"Cookie": "session=abc; x=<script>alert(1)</script>"}
            ) as websocket:
                assert websocket.receive_text() == "connected"

    assert any("[PASSIVE MODE]" in r.message for r in caplog.records)


def test_guard_websocket_redacts_sensitive_query_param_when_attack_detected(
    caplog: pytest.LogCaptureFixture,
    captured_events: list[dict[str, Any]],
) -> None:
    captured_on_block: list[dict[str, Any]] = []
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        log_sensitive_params=frozenset({"password"}),
        log_sensitive_headers=frozenset({"password"}),
        on_block=lambda request, payload: captured_on_block.append(payload),
    )
    app = _app_with_websocket(config)

    with caplog.at_level(logging.WARNING):
        with TestClient(app, client=("127.0.0.1", 20007)) as client:
            with pytest.raises(WebSocketDisconnect) as exc_info:
                with client.websocket_connect(
                    "/ws?password=SUPERSECRET&x=<script>alert(1)</script>"
                ):
                    pass

    assert exc_info.value.code == WS_CLOSE_SUSPICIOUS_ACTIVITY.code
    assert exc_info.value.reason == WS_CLOSE_SUSPICIOUS_ACTIVITY.reason
    assert not any("SUPERSECRET" in r.message for r in caplog.records)
    assert not any("SUPERSECRET" in str(event) for event in captured_events)
    assert captured_on_block
    assert not any("SUPERSECRET" in str(payload) for payload in captured_on_block)


def test_guard_websocket_redacts_sensitive_header_when_attack_detected(
    caplog: pytest.LogCaptureFixture,
    captured_events: list[dict[str, Any]],
) -> None:
    captured_on_block: list[dict[str, Any]] = []
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        log_sensitive_params=frozenset({"password"}),
        log_sensitive_headers=frozenset({"password"}),
        on_block=lambda request, payload: captured_on_block.append(payload),
    )
    app = _app_with_websocket(config)

    with caplog.at_level(logging.WARNING):
        with TestClient(app, client=("127.0.0.1", 20008)) as client:
            with pytest.raises(WebSocketDisconnect) as exc_info:
                with client.websocket_connect(
                    "/ws",
                    headers={
                        "Password": "SUPERSECRET",
                        "X-Evil": "<script>alert(1)</script>",
                    },
                ):
                    pass

    assert exc_info.value.code == WS_CLOSE_SUSPICIOUS_ACTIVITY.code
    assert exc_info.value.reason == WS_CLOSE_SUSPICIOUS_ACTIVITY.reason
    assert not any("SUPERSECRET" in r.message for r in caplog.records)
    assert not any("SUPERSECRET" in str(event) for event in captured_events)
    assert captured_on_block
    assert not any("SUPERSECRET" in str(payload) for payload in captured_on_block)


def test_guard_websocket_redacts_sensitive_cookie_when_attack_detected(
    caplog: pytest.LogCaptureFixture,
    captured_events: list[dict[str, Any]],
) -> None:
    captured_on_block: list[dict[str, Any]] = []
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        log_sensitive_params=frozenset({"password"}),
        log_sensitive_headers=frozenset({"password"}),
        on_block=lambda request, payload: captured_on_block.append(payload),
    )
    app = _app_with_websocket(config)

    with caplog.at_level(logging.WARNING):
        with TestClient(app, client=("127.0.0.1", 20009)) as client:
            with pytest.raises(WebSocketDisconnect) as exc_info:
                with client.websocket_connect(
                    "/ws",
                    headers={
                        "Cookie": (
                            "session=abc; password=SUPERSECRET; "
                            "x=<script>alert(1)</script>"
                        )
                    },
                ):
                    pass

    assert exc_info.value.code == WS_CLOSE_SUSPICIOUS_ACTIVITY.code
    assert exc_info.value.reason == WS_CLOSE_SUSPICIOUS_ACTIVITY.reason
    assert not any("SUPERSECRET" in r.message for r in caplog.records)
    assert not any("SUPERSECRET" in str(event) for event in captured_events)
    assert captured_on_block
    assert not any("SUPERSECRET" in str(payload) for payload in captured_on_block)


def test_guard_websocket_skips_detection_for_excluded_path() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        exclude_paths=["/ws"],
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 20010)) as client:
        with client.websocket_connect("/ws?q=<script>alert(1)</script>") as websocket:
            assert websocket.receive_text() == "connected"


def test_guard_websocket_skips_detection_for_whitelisted_ip() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        whitelist=("127.0.0.1",),
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 20011)) as client:
        with client.websocket_connect("/ws?q=<script>alert(1)</script>") as websocket:
            assert websocket.receive_text() == "connected"


@requires_whitelist_access_only
def test_ws_scans_a_whitelisted_client_under_access_only_whitelist() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        whitelist=("127.0.0.1",),
        whitelist_access_only=True,
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 20014)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws?q=<script>alert(1)</script>"):
                pass

    assert exc_info.value.code == WS_CLOSE_SUSPICIOUS_ACTIVITY.code


def test_guard_websocket_auto_bans_ip_after_repeated_suspicious_activity() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        enable_ip_banning=True,
        auto_ban_threshold=2,
        auto_ban_duration=60,
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("203.0.113.77", 20012)) as client:
        for _ in range(2):
            with pytest.raises(WebSocketDisconnect) as exc_info:
                with client.websocket_connect("/ws?q=<script>alert(1)</script>"):
                    pass
            assert exc_info.value.code == WS_CLOSE_SUSPICIOUS_ACTIVITY.code

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws?q=<script>alert(1)</script>"):
                pass

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "IP banned"


def test_make_guard_websocket_rejects_script_tag_without_middleware() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    app = _app_with_factory_websocket(config)

    with TestClient(app, client=("127.0.0.1", 20013)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws?q=<script>alert(1)</script>"):
                pass

    assert exc_info.value.code == WS_CLOSE_SUSPICIOUS_ACTIVITY.code
    assert exc_info.value.reason == WS_CLOSE_SUSPICIOUS_ACTIVITY.reason


def test_websocket_detection_middleware_resolves_geo_ip_handler_for_country_rules() -> (
    None
):
    handler = IPInfoManager("test-token", None)
    config = SecurityConfig(
        enable_redis=False,
        blocked_countries=frozenset({"CN"}),
        geo_ip_handler=handler,
    )

    middleware = _WebSocketDetectionMiddleware(config)

    assert middleware.geo_ip_handler is handler


def test_websocket_detection_middleware_has_no_geo_ip_handler_by_default() -> None:
    config = SecurityConfig(enable_redis=False)

    middleware = _WebSocketDetectionMiddleware(config)

    assert middleware.geo_ip_handler is None


async def test_websocket_detection_middleware_refresh_cloud_ip_ranges_noop() -> None:
    config = SecurityConfig(enable_redis=False)
    middleware = _WebSocketDetectionMiddleware(config)

    await middleware.refresh_cloud_ip_ranges()


async def _raise_detection_redis_error(*args: Any, **kwargs: Any) -> Any:
    raise GuardRedisError(503, "Redis operation failed")


def test_guard_websocket_closes_with_1013_when_detection_fails_secure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "guard_core.core.checks.helpers.detect_penetration_attempt",
        _raise_detection_redis_error,
    )
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        redis_fail_open=False,
        fail_secure=True,
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 20016)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == WS_CLOSE_SECURITY_CHECK_FAILED.code
    assert exc_info.value.reason == WS_CLOSE_SECURITY_CHECK_FAILED.reason


def test_guard_websocket_shares_auto_ban_counter_with_http_pipeline() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        enable_ip_banning=True,
        auto_ban_threshold=5,
        auto_ban_duration=60,
    )
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/http")
    async def http_endpoint() -> dict[str, bool]:
        return {"ok": True}

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    with TestClient(app, client=("198.51.100.201", 20017)) as client:
        for _ in range(3):
            response = client.get("/http?q=<script>alert(1)</script>")
            assert response.status_code == 400

        for _ in range(2):
            with pytest.raises(WebSocketDisconnect) as exc_info:
                with client.websocket_connect("/ws?q=<script>alert(1)</script>"):
                    pass
            assert exc_info.value.code == WS_CLOSE_SUSPICIOUS_ACTIVITY.code

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws?q=<script>alert(1)</script>"):
                pass

    assert exc_info.value.code == WS_CLOSE_IP_BANNED.code
    assert exc_info.value.reason == WS_CLOSE_IP_BANNED.reason


def test_make_guard_websocket_keeps_its_own_bucket_without_middleware() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        enable_ip_banning=True,
        auto_ban_threshold=5,
        auto_ban_duration=60,
    )
    app = FastAPI()

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(make_guard_websocket(config))
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    with TestClient(app, client=("198.51.100.202", 20018)) as client:
        for _ in range(3):
            with pytest.raises(WebSocketDisconnect) as exc_info:
                with client.websocket_connect("/ws?q=<script>alert(1)</script>"):
                    pass
            assert exc_info.value.code == WS_CLOSE_SUSPICIOUS_ACTIVITY.code

    detection_middleware = websocket_module._get_ws_detection_middleware(config)
    assert detection_middleware.suspicious_request_counts["198.51.100.202"]


def test_guard_websocket_ignores_http_pipeline_without_a_detection_check() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/http")
    async def http_endpoint() -> dict[str, bool]:
        return {"ok": True}

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    with TestClient(app, client=("127.0.0.1", 20019)) as client:
        assert client.get("/http").status_code == 200
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"


def test_resolve_shared_suspicious_counts_returns_none_without_a_matching_check() -> (
    None
):
    from types import SimpleNamespace

    from guard_core.core.checks.pipeline import SecurityCheckPipeline

    from guard._middleware_state import MiddlewareState, register_state

    config = SecurityConfig(enable_redis=False)
    register_state(
        config,
        None,
        MiddlewareState(
            security_pipeline=SecurityCheckPipeline([]),
            composite_handler=None,
            event_bus=None,
            metrics_collector=None,
            response_factory=None,
            validator=None,
            bypass_handler=None,
            behavioral_processor=None,
            handler_initializer=SimpleNamespace(redis_handler=None),
            agent_handler=None,
        ),
    )

    result = websocket_module._resolve_shared_suspicious_counts(FastAPI(), config)

    assert result is None
