from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.models import SecurityConfig

from guard import SecurityDecorator
from guard.middleware import SecurityMiddleware
from tests.live_smoke.scenarios.rate_limit_and_bans import _build_single_entry_mmdb

CLIENT_IP = "203.0.113.5"


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


def _config(
    tmp_path: Path, blocked_countries: frozenset[str] = frozenset()
) -> SecurityConfig:
    db_path = tmp_path / "geo.mmdb"
    db_path.write_bytes(_build_single_entry_mmdb(CLIENT_IP, "CN"))
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        ipinfo_token="tok",
        ipinfo_db_path=db_path,
        lazy_init=False,
        blocked_countries=blocked_countries,
    )


def _app(config: SecurityConfig) -> FastAPI:
    app = FastAPI()
    decorator = SecurityDecorator(config)

    @app.get("/blocked")
    @decorator.block_countries(["CN"])
    async def blocked() -> dict[str, str]:
        return {"route": "blocked"}

    @app.get("/open")
    async def open_route() -> dict[str, str]:
        return {"route": "open"}

    app.add_middleware(SecurityMiddleware, config=config)
    app.state.guard_decorator = decorator
    return app


def _status(app: FastAPI, path: str) -> int:
    with TestClient(app, client=(CLIENT_IP, 5555)) as client:
        return client.get(path).status_code


def test_global_blocked_countries_from_the_token_block(tmp_path: Path) -> None:
    app = _app(_config(tmp_path, blocked_countries=frozenset({"CN"})))

    assert _status(app, "/open") == 403


def test_route_block_countries_blocks_without_a_global_country_rule(
    tmp_path: Path,
) -> None:
    app = _app(_config(tmp_path))

    assert _status(app, "/blocked") == 403
    assert _status(app, "/open") == 200
