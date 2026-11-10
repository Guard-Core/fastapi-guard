from __future__ import annotations

import asyncio
import ipaddress
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from guard_core.decorators import SecurityDecorator
from httpx import ASGITransport, AsyncClient

from guard import SecurityConfig, SecurityMiddleware

AWS_RANGE = ipaddress.ip_network("198.51.100.0/24")
CLIENT = ("198.51.100.77", 50000)


def _app() -> FastAPI:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        lazy_init=False,
    )
    app = FastAPI()
    decorator = SecurityDecorator(config)

    @decorator.block_clouds(["AWS"])
    @app.get("/r")
    async def route() -> dict[str, str]:
        return {"ok": "yes"}

    app.add_middleware(SecurityMiddleware, config=config)
    app.state.guard_decorator = decorator
    return app


async def test_a_route_only_block_clouds_loads_its_ranges_and_blocks() -> None:
    with patch(
        "guard_core.handlers.cloud_handler._fetch_provider_ranges",
        new=AsyncMock(return_value=({AWS_RANGE}, {})),
    ) as fetch_aws:
        async with AsyncClient(
            transport=ASGITransport(app=_app(), client=CLIENT), base_url="http://test"
        ) as client:
            response = await client.get("/r")
            await asyncio.sleep(0.5)
            response = await client.get("/r")

    fetch_aws.assert_awaited_with("AWS")
    assert response.status_code == 403
