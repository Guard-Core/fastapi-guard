import os

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from guard import PureASGISecurityMiddleware, SecurityConfig, SecurityMiddleware

ORIGIN_A = "https://a.example"
ORIGIN_B = "https://b.example"


REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"


def _app(
    middleware: type[SecurityMiddleware] | type[PureASGISecurityMiddleware],
    name: str,
    origin: str,
    max_age: int,
    redis: bool = False,
) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        middleware,
        config=SecurityConfig(
            enable_redis=redis,
            redis_url=REDIS_URL if redis else None,
            redis_prefix="wp102:",
            enable_rate_limiting=False,
            enable_ip_banning=False,
            enable_cors=True,
            cors_allow_origins=[origin],
            security_headers={
                "enabled": True,
                "csp": {"default-src": ["'self'", f"https://{name}.csp.example"]},
                "hsts": {"max_age": max_age, "include_subdomains": True},
                "frame_options": "DENY" if name == "a" else "SAMEORIGIN",
                "custom": {"X-App-Name": name},
            },
        ),
    )

    @app.get("/x")
    async def x() -> dict[str, bool]:
        return {"ok": True}

    return app


async def _get(app: FastAPI, origin: str) -> dict[str, str]:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        return dict((await client.get("/x", headers={"Origin": origin})).headers)


@pytest.mark.parametrize("redis", [False, True])
async def test_two_apps_in_one_process_each_answer_with_their_own_headers(
    redis: bool,
) -> None:
    for middleware in (SecurityMiddleware, PureASGISecurityMiddleware):
        app_a = _app(middleware, "a", ORIGIN_A, 31536000, redis)
        app_b = _app(middleware, "b", ORIGIN_B, 63072000, redis)
        for _ in range(2):
            a = await _get(app_a, ORIGIN_A)
            b = await _get(app_b, ORIGIN_B)
            assert a["content-security-policy"].endswith("https://a.csp.example")
            assert b["content-security-policy"].endswith("https://b.csp.example")
            assert a["strict-transport-security"].startswith("max-age=31536000")
            assert b["strict-transport-security"].startswith("max-age=63072000")
            assert a["x-app-name"] == "a"
            assert b["x-app-name"] == "b"
            assert a["x-frame-options"] == "DENY"
            assert b["x-frame-options"] == "SAMEORIGIN"
            assert a["access-control-allow-origin"] == ORIGIN_A
            assert b["access-control-allow-origin"] == ORIGIN_B
            cross = await _get(app_a, ORIGIN_B)
            assert "access-control-allow-origin" not in cross
