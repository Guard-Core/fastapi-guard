import os
from collections.abc import AsyncGenerator

import pytest
from fastapi import FastAPI
from guard_core.handlers.security_headers_handler import security_headers_manager
from httpx import ASGITransport, AsyncClient

from guard import PureASGISecurityMiddleware, SecurityConfig, SecurityMiddleware

APP_CSP = {"default-src": ["'self'", "https://app.example"]}
GLOBAL_CSP = {"default-src": ["'self'", "https://global.example"]}
REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"


@pytest.fixture(autouse=True)
async def _clean_global_manager() -> AsyncGenerator[None, None]:
    await security_headers_manager.reset()
    yield
    await security_headers_manager.reset()


def _app(middleware: type, **config: object) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        middleware,  # type: ignore[arg-type]
        config=SecurityConfig(
            enable_redis=False,
            enable_rate_limiting=False,
            enable_ip_banning=False,
            security_headers={"enabled": True, "csp": APP_CSP, "frame_options": "DENY"},
            **config,  # type: ignore[arg-type]
        ),
    )

    @app.get("/x")
    async def x() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/y")
    async def y() -> dict[str, bool]:
        return {"ok": True}

    return app


async def _get(app: FastAPI, path: str) -> dict[str, str]:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        return dict((await client.get(path)).headers)


@pytest.mark.parametrize("middleware", [SecurityMiddleware, PureASGISecurityMiddleware])
async def test_the_global_configure_reaches_a_guarded_app(middleware: type) -> None:
    app = _app(middleware)
    assert (await _get(app, "/x"))["content-security-policy"].endswith("app.example")

    security_headers_manager.configure(csp=GLOBAL_CSP)

    for path in ("/x", "/y"):
        headers = await _get(app, path)
        assert headers["content-security-policy"] == (
            "default-src 'self' https://global.example"
        )
        assert headers["x-frame-options"] == "DENY"


@pytest.mark.parametrize("middleware", [SecurityMiddleware, PureASGISecurityMiddleware])
async def test_without_a_global_call_the_app_keeps_its_own_config(
    middleware: type,
) -> None:
    headers = await _get(_app(middleware), "/x")

    assert headers["content-security-policy"].endswith("app.example")


@pytest.mark.parametrize("middleware", [SecurityMiddleware, PureASGISecurityMiddleware])
async def test_the_response_manager_reaches_the_redis_of_its_app(
    middleware: type,
) -> None:
    instance = middleware(
        FastAPI(),
        config=SecurityConfig(
            enable_redis=True,
            redis_url=REDIS_URL,
            security_headers={"enabled": True},
        ),
    )
    engine = instance if middleware is SecurityMiddleware else instance._engine

    assert engine.response_factory.security_headers_manager.redis_handler is (
        engine.redis_handler
    )
    assert engine.redis_handler is not None


@pytest.mark.parametrize("middleware", [SecurityMiddleware, PureASGISecurityMiddleware])
async def test_building_a_second_app_does_not_override_the_first(
    middleware: type,
) -> None:
    first = _app(middleware)
    second = FastAPI()
    second.add_middleware(
        middleware,  # type: ignore[arg-type]
        config=SecurityConfig(
            enable_redis=False,
            enable_rate_limiting=False,
            enable_ip_banning=False,
            security_headers={"enabled": True, "csp": GLOBAL_CSP},
        ),
    )

    @second.get("/x")
    async def x() -> dict[str, bool]:
        return {"ok": True}

    await _get(first, "/x")
    await _get(second, "/x")

    assert (await _get(first, "/x"))["content-security-policy"].endswith("app.example")
    assert (await _get(second, "/x"))["content-security-policy"].endswith(
        "global.example"
    )
