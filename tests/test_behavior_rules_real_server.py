"""Behavior rules on a real uvicorn server, classic and pure ASGI middleware."""

import itertools
import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import httpx
import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from guard_core.decorators import SecurityDecorator
from guard_core.models import BehaviorRuleConfig, SecurityConfig

from guard import PureASGISecurityMiddleware, SecurityMiddleware

_IP = itertools.count(1)


def _unique_ip() -> str:
    n = next(_IP)
    return f"203.0.{n // 250 + 50}.{(n % 250) + 1}"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def _serve(app: FastAPI) -> Iterator[int]:
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            proxy_headers=False,
            lifespan="off",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        assert time.time() < deadline, "uvicorn did not start"
        time.sleep(0.02)
    try:
        yield port
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "enable_ip_banning": True,
        "trusted_proxies": ["127.0.0.1"],
        "passive_mode": False,
        "ban_on_hostile_signals": False,
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


def _build_app(
    middleware: Any, config: SecurityConfig, route_rule: bool = False
) -> FastAPI:
    app = FastAPI()
    guard = SecurityDecorator(config)
    app.state.guard_decorator = guard

    @app.get("/ping")
    async def ping() -> dict[str, bool]:
        return {"ok": True}

    async def missing() -> JSONResponse:
        return JSONResponse({"error": "boom"}, status_code=404)

    if route_rule:
        missing = guard.return_monitor("status:404", 2, 60, "ban")(missing)
    app.get("/missing")(missing)

    @app.get("/boom")
    async def boom() -> JSONResponse:
        return JSONResponse({"error": "boom"}, status_code=200)

    app.add_middleware(middleware, config=config)
    return app


def _statuses(
    middleware: Any,
    config_factory: Callable[[], SecurityConfig],
    paths: list[str],
    route_rule: bool = False,
) -> list[int]:
    app = _build_app(middleware, config_factory(), route_rule)
    ip = _unique_ip()
    with _serve(app) as port:
        with httpx.Client(base_url=f"http://127.0.0.1:{port}") as client:
            return [
                client.get(path, headers={"X-Forwarded-For": ip}).status_code
                for path in paths
            ]


def _same_on_both(
    config_factory: Callable[[], SecurityConfig],
    paths: list[str],
    route_rule: bool = False,
) -> tuple[list[int], list[int]]:
    classic = _statuses(SecurityMiddleware, config_factory, paths, route_rule)
    pure = _statuses(PureASGISecurityMiddleware, config_factory, paths, route_rule)
    return classic, pure


def _global_404_ban() -> SecurityConfig:
    return _config(
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="return_pattern",
                threshold=2,
                window=60,
                pattern="status:404",
                action="ban",
            ),
        )
    )


def _global_usage_ban() -> SecurityConfig:
    return _config(
        global_behavior_rules=(
            BehaviorRuleConfig(rule_type="usage", threshold=2, window=60, action="ban"),
        )
    )


def _global_body_pattern_ban() -> SecurityConfig:
    return _config(
        behavior_scan_response_body=True,
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="return_pattern",
                threshold=1,
                window=60,
                pattern="json:error==boom",
                action="ban",
            ),
        ),
    )


def test_global_status_return_rule_bans_on_both_middlewares() -> None:
    classic, pure = _same_on_both(_global_404_ban, ["/missing"] * 4 + ["/ping"])
    assert 403 in classic
    assert pure == classic


def test_route_return_rule_bans_on_both_middlewares() -> None:
    classic, pure = _same_on_both(
        lambda: _config(), ["/missing"] * 4 + ["/ping"], route_rule=True
    )
    assert 403 in classic
    assert pure == classic


def test_global_usage_rule_bans_on_both_middlewares() -> None:
    classic, pure = _same_on_both(_global_usage_ban, ["/ping"] * 5)
    assert 403 in classic
    assert pure == classic


def test_global_body_pattern_rule_bans_on_both_middlewares() -> None:
    classic, pure = _same_on_both(_global_body_pattern_ban, ["/boom"] * 4)
    assert 403 in classic
    assert pure == classic


@pytest.mark.parametrize("middleware", [SecurityMiddleware, PureASGISecurityMiddleware])
def test_rules_stay_quiet_below_the_threshold(middleware: Any) -> None:
    statuses = _statuses(middleware, _global_404_ban, ["/missing", "/ping", "/ping"])
    assert statuses == [404, 200, 200]


def _throttle_app(middleware: Any, config: SecurityConfig) -> FastAPI:
    app = FastAPI()
    guard = SecurityDecorator(config)
    app.state.guard_decorator = guard

    @app.get("/missing")
    async def missing() -> JSONResponse:
        return JSONResponse({"error": "gone"}, status_code=404)

    @app.get("/ping")
    async def ping() -> dict[str, bool]:
        return {"ok": True}

    app.add_middleware(middleware, config=config)
    return app


def _responses(
    middleware: Any, config: SecurityConfig, paths: list[str]
) -> list[tuple[int, str | None]]:
    app = _throttle_app(middleware, config)
    ip = _unique_ip()
    with _serve(app) as port:
        with httpx.Client(base_url=f"http://127.0.0.1:{port}") as client:
            responses = [
                client.get(path, headers={"X-Forwarded-For": ip}) for path in paths
            ]
    return [(r.status_code, r.headers.get("Retry-After")) for r in responses]


@pytest.mark.parametrize("middleware", [SecurityMiddleware, PureASGISecurityMiddleware])
def test_global_return_rule_halves_its_threshold_after_a_detection_hit(
    middleware: Any,
) -> None:
    config = _config(
        enable_penetration_detection=True,
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="return_pattern",
                threshold=4,
                window=60,
                pattern="status:404",
                action="ban",
                correlate_with_detection=True,
            ),
        ),
    )
    paths = ["/ping?q=<script>alert(1)</script>"] + ["/missing"] * 4 + ["/ping"]
    statuses = [status for status, _ in _responses(middleware, config, paths)]
    assert statuses[1:] == [404, 404, 404, 403, 403]
