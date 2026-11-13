from __future__ import annotations

from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.models import SecurityConfig
from starlette.types import ASGIApp

from guard.asgi import PureASGISecurityMiddleware
from guard.lifespan import (
    _built_security_middleware,
    _find_security_config,
    _find_security_middleware,
    guard_lifespan,
)
from guard.middleware import SecurityMiddleware
from guard.status import add_status_route

CLASSES = [
    pytest.param(SecurityMiddleware, id="classic"),
    pytest.param(PureASGISecurityMiddleware, id="pure"),
]


def _app(cls: Callable[..., ASGIApp]) -> tuple[FastAPI, SecurityConfig]:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    app = FastAPI(lifespan=guard_lifespan)
    app.add_middleware(cls, config=config)
    return app, config


@pytest.mark.parametrize("cls", CLASSES)
def test_the_config_is_found_for_each_class(cls: Any) -> None:
    app, config = _app(cls)

    assert _find_security_config(app) is config


@pytest.mark.parametrize("cls", CLASSES)
def test_the_lifespan_releases_the_app_on_shutdown_for_each_class(cls: Any) -> None:
    app, config = _app(cls)

    with patch("guard.lifespan.release_app") as released:
        with TestClient(app, client=("127.0.0.1", 12345)):
            pass

    released.assert_called_once_with(config)


@pytest.mark.parametrize("cls", CLASSES)
def test_add_status_route_accepts_each_class_and_answers(cls: Any) -> None:
    app, _ = _app(cls)
    add_status_route(app)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        response = client.get("/_guard/status")

    assert response.status_code == 200
    assert "geo_ip" in response.json()


@pytest.mark.parametrize("cls", CLASSES)
def test_the_lookup_finds_the_built_instance_without_building_another(
    cls: Any,
) -> None:
    app, _ = _app(cls)

    with TestClient(app, client=("127.0.0.1", 12345)):
        found = _find_security_middleware(app)
        built = _built(app)

        assert found is built
        assert not hasattr(app.state, "_guard_cold_security_middleware")


def test_the_status_route_reports_the_instance_that_serves_requests() -> None:
    app, _ = _app(SecurityMiddleware)
    add_status_route(app)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        served = _built_security_middleware(app)
        with patch.object(
            served, "get_initialization_status", return_value={"served": True}
        ):
            body = client.get("/_guard/status").json()

    assert body == {"served": True}


def _built(app: FastAPI) -> SecurityMiddleware | None:
    return _built_security_middleware(app)
