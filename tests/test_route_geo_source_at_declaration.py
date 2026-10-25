import logging
from collections.abc import Callable
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.models import SecurityConfig

from guard import SecurityDecorator
from guard.middleware import SecurityMiddleware

MAKERS: list[Callable[[SecurityDecorator], Any]] = [
    lambda d: d.block_countries(["CN"]),
    lambda d: d.allow_countries(["US"]),
    lambda d: d.geo_rate_limit({"US": (5, 60), "*": (50, 60)}),
]


async def _route() -> dict[str, str]:
    return {"route": "ok"}


@pytest.mark.parametrize("make", MAKERS)
def test_a_geo_rule_without_a_geo_source_refuses_at_declaration(
    make: Callable[[SecurityDecorator], Any],
) -> None:
    decorator = SecurityDecorator(SecurityConfig(enable_redis=False))

    with pytest.raises(ValueError, match="no GeoIP database is configured"):
        make(decorator)(_route)


@pytest.mark.parametrize("make", MAKERS)
def test_false_declares_and_the_startup_report_warns_once(
    make: Callable[[SecurityDecorator], Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        fail_on_misconfiguration=False,
    )
    decorator = SecurityDecorator(config)
    app = FastAPI()
    app.get("/geo")(make(decorator)(_route))
    app.add_middleware(SecurityMiddleware, config=config)
    app.state.guard_decorator = decorator

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        with TestClient(app) as client:
            client.get("/geo")
            client.get("/geo")

    assert caplog.text.count("no GeoIP database") == 1


@pytest.mark.parametrize("make", MAKERS)
def test_a_token_means_the_rule_declares(
    make: Callable[[SecurityDecorator], Any],
) -> None:
    decorator = SecurityDecorator(SecurityConfig(enable_redis=False, ipinfo_token="t"))

    make(decorator)(_route)


def test_a_token_without_the_downloader_refuses_at_declaration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("guard_core._geo_source._extra_installed", lambda name: False)
    decorator = SecurityDecorator(SecurityConfig(enable_redis=False, ipinfo_token="t"))

    with pytest.raises(ValueError, match="'maxminddb' and 'aiohttp'"):
        decorator.block_countries(["CN"])(_route)


def test_the_two_config_case_refuses_at_declaration() -> None:
    middleware_config = SecurityConfig(enable_redis=False, ipinfo_token="t")
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=middleware_config)
    decorator = SecurityDecorator(SecurityConfig(enable_redis=False))

    with pytest.raises(ValueError, match="no GeoIP database is configured"):
        decorator.block_countries(["CN"])(_route)
