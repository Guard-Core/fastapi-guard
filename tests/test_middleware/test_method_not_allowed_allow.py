from typing import Any

import pytest
from fastapi import FastAPI
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from httpx import ASGITransport, AsyncClient

from guard import SecurityConfig
from guard.asgi import PureASGISecurityMiddleware
from guard.middleware import SecurityMiddleware

# guard-core 4.5.0 answers 405 with Allow for a served path under another method;
# the 4.4.0 engine answered 500 without it. The marker is the per-middleware
# headers manager of 4.5.0.
_ENGINE_ANSWERS_405 = hasattr(SecurityHeadersManager, "isolated")


def _app(middleware: Any) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        middleware,
        config=SecurityConfig(
            enable_redis=False,
            enable_rate_limiting=False,
            enable_ip_banning=False,
            route_resolution_strict=True,
        ),
    )

    @app.get("/items")
    async def read_items() -> dict[str, str]:
        return {"ok": "yes"}

    @app.api_route("/things", methods=["PUT", "POST"])
    async def write_things() -> dict[str, str]:
        return {"ok": "yes"}

    return app


async def _send(app: FastAPI, method: str, path: str) -> tuple[int, str | None]:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.request(method, path)
    return response.status_code, response.headers.get("allow")


@pytest.mark.parametrize("middleware", [SecurityMiddleware, PureASGISecurityMiddleware])
@pytest.mark.parametrize(
    ("method", "path", "allow"),
    [("POST", "/items", "GET"), ("DELETE", "/things", "POST, PUT")],
)
async def test_a_wrong_method_is_a_405_listing_the_methods_the_route_accepts(
    middleware: Any, method: str, path: str, allow: str
) -> None:
    status, allowed = await _send(_app(middleware), method, path)

    if _ENGINE_ANSWERS_405:
        assert (status, allowed) == (405, allow)
    else:
        assert (status, allowed) == (500, None)


@pytest.mark.parametrize("middleware", [SecurityMiddleware, PureASGISecurityMiddleware])
async def test_a_path_no_route_serves_is_a_404_without_allow(
    middleware: Any,
) -> None:
    status, allowed = await _send(_app(middleware), "GET", "/nothing")

    assert (status, allowed) == ((404 if _ENGINE_ANSWERS_405 else 500), None)


@pytest.mark.parametrize("middleware", [SecurityMiddleware, PureASGISecurityMiddleware])
async def test_the_served_method_is_not_refused(middleware: Any) -> None:
    assert await _send(_app(middleware), "GET", "/items") == (200, None)
