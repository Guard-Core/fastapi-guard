import pytest
from fastapi import FastAPI
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig
from httpx import ASGITransport, AsyncClient

from guard.middleware import SecurityMiddleware


def test_middleware_construction_with_hsts_none_does_not_raise() -> None:
    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        security_headers={"enabled": True, "hsts": None},
    )
    middleware = SecurityMiddleware(app, config=config)
    assert middleware is not None


@pytest.mark.asyncio
async def test_request_with_hsts_none_does_not_500() -> None:
    await security_headers_manager.reset()

    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        security_headers={"enabled": True, "hsts": None},
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert "strict-transport-security" not in response.headers


@pytest.mark.asyncio
async def test_hsts_none_configures_manager_without_hsts() -> None:
    await security_headers_manager.reset()
    security_headers_manager.enabled = False
    config = SecurityConfig(
        enable_penetration_detection=False,
        security_headers={"enabled": True, "hsts": None},
    )
    SecurityMiddleware(FastAPI(), config=config)
    assert security_headers_manager.enabled is True
    assert security_headers_manager.hsts_config is None
