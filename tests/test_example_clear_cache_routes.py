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
