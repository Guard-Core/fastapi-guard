import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.models import SecurityConfig

from guard import SecurityDecorator
from guard.middleware import SecurityMiddleware


async def _route() -> dict[str, str]:
    return {"route": "ok"}


def test_decorator_false_under_middleware_true_starts_and_answers(
    caplog: pytest.LogCaptureFixture,
) -> None:
    middleware_config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        fail_on_misconfiguration=True,
    )
    decorator = SecurityDecorator(
        SecurityConfig(enable_redis=False, fail_on_misconfiguration=False)
    )
    app = FastAPI()
    app.get("/geo")(decorator.block_countries(["CN"])(_route))
    app.add_middleware(SecurityMiddleware, config=middleware_config)
    app.state.guard_decorator = decorator

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        with TestClient(app, client=("203.0.113.5", 50000)) as client:
            first = client.get("/geo")
            second = client.get("/geo")

    assert (first.status_code, second.status_code) == (200, 200)
    assert caplog.text.count("no GeoIP database") == 1
