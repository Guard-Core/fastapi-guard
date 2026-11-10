import asyncio
import os
import uuid

import httpx
from fastapi import FastAPI
from guard_core.models import SecurityConfig

from guard.middleware import SecurityMiddleware
from tests.redis_isolation import suite_redis_prefix

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        SecurityMiddleware,
        config=SecurityConfig(
            enable_redis=True,
            redis_url=REDIS_URL,
            redis_prefix=suite_redis_prefix(f"wp537{uuid.uuid4().hex[:8]}"),
            enable_penetration_detection=False,
            enable_rate_limiting=True,
            rate_limit=100,
            rate_limit_window=60,
        ),
    )

    @app.get("/")
    async def index() -> dict[str, str]:
        return {"ok": "yes"}

    return app


async def _get_status(app: FastAPI) -> int:
    transport = httpx.ASGITransport(app=app, client=("203.0.113.9", 1234))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        return (await client.get("/")).status_code


def test_the_first_request_of_a_second_event_loop_is_served_not_a_503() -> None:
    app = _app()

    statuses = [asyncio.run(_get_status(app)) for _ in range(3)]

    assert statuses == [200, 200, 200]
