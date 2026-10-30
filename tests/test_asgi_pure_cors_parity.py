from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig

from guard import PureASGISecurityMiddleware, SecurityMiddleware

ORIGIN = "https://a.example"


@pytest.fixture(autouse=True)
async def _reset_headers_manager() -> AsyncIterator[None]:
    await security_headers_manager.reset()
    yield
    await security_headers_manager.reset()


def _cors_headers(middleware: type[Any], config: SecurityConfig) -> dict[str, str]:
    app = FastAPI()
    app.add_middleware(middleware, config=config)

    @app.get("/x")
    async def x() -> dict[str, int]:
        return {"ok": 1}

    security_headers_manager.configure(
        enable_cors=True,
        cors_origins=[ORIGIN],
        cors_allow_methods=["GET"],
        override_apps=True,
    )
    with TestClient(app, client=("203.0.113.5", 5000)) as client:
        response = client.get("/x", headers={"Origin": ORIGIN})
    return {k: v for k, v in response.headers.items() if k.startswith("access-")}


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_rate_limiting=False,
        enable_cors=False,
        trusted_proxies=[],
    )


async def test_a_runtime_cors_override_reaches_a_normal_response_like_the_classic() -> (
    None
):
    classic = _cors_headers(SecurityMiddleware, _config())
    await security_headers_manager.reset()
    pure = _cors_headers(PureASGISecurityMiddleware, _config())

    assert classic["access-control-allow-origin"] == ORIGIN
    assert pure == classic
