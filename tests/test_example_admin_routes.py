import importlib
import importlib.util
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
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

        response = client.post("/admin/clear-cache")

        assert response.status_code == 200
        assert not portal.call(bans.is_ip_banned, BANNED_IP)
        assert not windows.request_timestamps.get(WINDOWED_IP)
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
    assert config.emergency_mode is True
    assert outsider.get("/").status_code == 503
    assert admin.get("/").status_code == 200

    off = admin.put("/admin/emergency-mode", json=False)
    assert off.json()["details"]["emergency_mode"] is False
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
    example: tuple[FastAPI, SecurityConfig],
) -> None:
    app, config = example
    config.agent_api_key = "test-key"
    config.enable_agent = True
    config.enable_dynamic_rules = True
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
