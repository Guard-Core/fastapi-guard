import importlib
import importlib.util
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
import redis
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.models import SecurityConfig

SIMPLE_APP_MAIN = (
    Path(__file__).resolve().parents[1] / "examples" / "simple_app" / "main.py"
)
BANNED_IP = "203.0.113.5"
WINDOWED_IP = "203.0.113.6"
REDIS_WINDOWED_IP = "203.0.113.7"


def _redis_window_keys(config: SecurityConfig, ip: str) -> list[str]:
    client = redis.Redis.from_url(config.redis_url or "", decode_responses=True)
    try:
        return sorted(client.scan_iter(f"{config.redis_prefix}rate_limit:rate:{ip}*"))
    finally:
        client.close()


def _simple_app(monkeypatch: pytest.MonkeyPatch) -> tuple[FastAPI, SecurityConfig]:
    monkeypatch.setenv("IPINFO_TOKEN", "test_token")
    spec = importlib.util.spec_from_file_location("simple_app_main", SIMPLE_APP_MAIN)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app, module.security_config


def _advanced_app(advanced_app_main: Any) -> tuple[FastAPI, SecurityConfig]:
    security = importlib.import_module("app.security")
    return advanced_app_main.app, security.security_config


@pytest.fixture(params=["simple_app", "advanced_app"])
def example(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> tuple[FastAPI, SecurityConfig]:
    builders: dict[str, Callable[[], tuple[FastAPI, SecurityConfig]]] = {
        "simple_app": lambda: _simple_app(monkeypatch),
        "advanced_app": lambda: _advanced_app(
            request.getfixturevalue("advanced_app_main")
        ),
    }
    return builders[request.param]()


def test_clear_cache_route_drops_the_bans_and_the_rate_windows(
    example: tuple[FastAPI, SecurityConfig],
) -> None:
    app, config = example
    assert config.redis_prefix != "fastapi_guard:", "set REDIS_PREFIX before the reset"

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        portal = client.portal
        assert portal is not None
        bans = ip_ban_manager_for(config)
        windows = RateLimitManager(config)
        portal.call(bans.ban_ip, BANNED_IP, 300, "test")
        windows.request_timestamps[WINDOWED_IP].append(time.time())
        assert portal.call(bans.is_ip_banned, BANNED_IP)
        assert windows.request_timestamps[WINDOWED_IP]
        visitor = TestClient(app, client=(REDIS_WINDOWED_IP, 50000))
        assert visitor.get("/").status_code == 200
        assert _redis_window_keys(config, REDIS_WINDOWED_IP)

        response = client.post("/admin/clear-cache")

        assert response.status_code == 200
        assert not portal.call(bans.is_ip_banned, BANNED_IP)
        assert not windows.request_timestamps.get(WINDOWED_IP)
        assert not _redis_window_keys(config, REDIS_WINDOWED_IP)
        assert "geo_cache" not in response.text


def test_clear_cache_route_stays_behind_the_localhost_gate(
    example: tuple[FastAPI, SecurityConfig],
) -> None:
    app, _ = example
    with TestClient(app, client=("203.0.113.5", 50000)) as client:
        assert client.post("/admin/clear-cache").status_code == 403


def test_unban_route_lifts_the_ban_it_names(
    example: tuple[FastAPI, SecurityConfig],
) -> None:
    app, config = example
    assert config.redis_prefix != "fastapi_guard:", "set REDIS_PREFIX before the unban"

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        portal = client.portal
        assert portal is not None
        bans = ip_ban_manager_for(config)
        portal.call(bans.ban_ip, BANNED_IP, 300, "test")
        assert portal.call(bans.is_ip_banned, BANNED_IP)

        response = client.post("/admin/unban-ip", json=BANNED_IP)

        assert response.status_code == 200
        assert not portal.call(bans.is_ip_banned, BANNED_IP)
        assert response.json()["details"]["ip"] == BANNED_IP


@pytest.mark.parametrize("garbage", ["not-an-ip", "203.0.113.0/24", "", "1.2.3.999"])
def test_unban_route_refuses_input_that_is_not_an_ip(
    example: tuple[FastAPI, SecurityConfig], garbage: str
) -> None:
    app, _ = example
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        assert client.post("/admin/unban-ip", json=garbage).status_code == 400


OUTSIDER = ("203.0.113.9", 50000)
LOCAL = ("127.0.0.1", 50000)


def test_emergency_switch_refuses_outsiders_and_keeps_the_admin(
    example: tuple[FastAPI, SecurityConfig],
) -> None:
    app, config = example
    admin = TestClient(app, client=LOCAL)
    outsider = TestClient(app, client=OUTSIDER)
    assert outsider.get("/").status_code == 200

    on = admin.put("/admin/emergency-mode", json=True)
    assert on.status_code == 200
    assert on.json()["details"]["emergency_mode"] is True
    assert on.json()["details"]["added_to_emergency_whitelist"] == ["127.0.0.1"]
    assert on.json()["details"]["emergency_whitelist"] == ["127.0.0.1"]
    assert config.emergency_mode is True
    assert outsider.get("/").status_code == 503
    assert admin.get("/").status_code == 200

    off = admin.put("/admin/emergency-mode", json=False)
    assert off.json()["details"]["emergency_mode"] is False
    assert off.json()["details"]["removed_from_emergency_whitelist"] == ["127.0.0.1"]
    assert config.emergency_whitelist == []
    assert outsider.get("/").status_code == 200
    assert admin.get("/").status_code == 200


@pytest.mark.parametrize("body", ["yes", 1, None, {"enable": True}])
def test_emergency_switch_refuses_a_body_that_is_not_a_boolean(
    example: tuple[FastAPI, SecurityConfig], body: object
) -> None:
    app, config = example
    response = TestClient(app, client=LOCAL).put("/admin/emergency-mode", json=body)
    assert response.status_code == 400
    assert config.emergency_mode is False


def test_emergency_switch_defers_to_the_dashboard_when_dynamic_rules_are_on(
    example: tuple[FastAPI, SecurityConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, config = example
    monkeypatch.setattr("guard_agent.GuardAgentHandler", lambda config: AsyncMock())
    monkeypatch.setattr(config, "agent_api_key", "test-key")
    monkeypatch.setattr(config, "enable_agent", True)
    monkeypatch.setattr(config, "enable_dynamic_rules", True)
    response = TestClient(app, client=LOCAL).put("/admin/emergency-mode", json=True)
    assert response.status_code == 409
    assert "dashboard" in response.text
    assert config.emergency_mode is False


def test_stats_come_from_the_engine_and_carry_no_invented_numbers(
    example: tuple[FastAPI, SecurityConfig],
) -> None:
    app, config = example
    with TestClient(app, client=LOCAL) as client:
        portal = client.portal
        assert portal is not None
        bans = ip_ban_manager_for(config)
        before = client.get("/admin/stats").json()
        portal.call(bans.ban_ip, BANNED_IP, 300, "test")
        after = client.get("/admin/stats").json()
        portal.call(bans.unban_ip, BANNED_IP)
        lifted = client.get("/admin/stats").json()

    assert BANNED_IP not in before["banned_ips"]
    assert BANNED_IP in after["banned_ips"]
    assert BANNED_IP not in lifted["banned_ips"]
    assert not {"total_requests", "blocked_requests", "suspicious_activities"} & set(
        after
    )
    assert after["active_rules"]["rate_limit"] == config.rate_limit


def test_stats_name_redis_as_the_store_when_redis_holds_the_windows(
    example: tuple[FastAPI, SecurityConfig],
) -> None:
    app, config = example
    visitor = TestClient(app, client=("203.0.113.5", 50000))
    for _ in range(5):
        assert visitor.get("/").status_code == 200
    assert _redis_window_keys(config, "203.0.113.5")

    stats = TestClient(app, client=LOCAL).get("/admin/stats").json()

    assert stats["rate_limit_store"] == "redis"
    assert stats["rate_limit_windows"] is None
    assert stats["redis_prefix"] == config.redis_prefix


def test_stats_count_the_process_windows_when_redis_is_off(
    example: tuple[FastAPI, SecurityConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, config = example
    monkeypatch.setattr(config, "enable_redis", False)
    RateLimitManager(config).request_timestamps[WINDOWED_IP].append(time.time())

    stats = TestClient(app, client=LOCAL).get("/admin/stats").json()

    assert stats["rate_limit_store"] == "memory"
    assert stats["rate_limit_windows"][WINDOWED_IP] == 1
    assert stats["redis_prefix"] is None


def test_emergency_switch_leaves_a_whitelist_it_did_not_extend_alone(
    example: tuple[FastAPI, SecurityConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, config = example
    monkeypatch.setattr(config, "emergency_whitelist", ["127.0.0.1"])
    admin = TestClient(app, client=LOCAL)

    on_response = admin.put("/admin/emergency-mode", json=True)
    assert on_response.status_code == 200, on_response.text
    on = on_response.json()["details"]
    off = admin.put("/admin/emergency-mode", json=False).json()["details"]

    assert on["added_to_emergency_whitelist"] == []
    assert off["removed_from_emergency_whitelist"] == []
    assert config.emergency_whitelist == ["127.0.0.1"]
