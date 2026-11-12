"""A probe path is clean when the app declares it as a literal route, and stays
flagged when it is undeclared or served by a catch-all or converter route
(LEDGER 6.869)."""

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from guard import SecurityConfig
from guard.middleware import SecurityMiddleware

PROBE = "/wp-login.php"


def _app(route: str | None) -> FastAPI:
    app = FastAPI()
    if route is not None:

        async def handler() -> JSONResponse:
            return JSONResponse(status_code=404, content={"detail": "Not Found"})

        app.add_api_route(route, handler, methods=["GET"])
    app.add_middleware(
        SecurityMiddleware,
        config=SecurityConfig(
            enable_redis=False,
            security_headers=None,
            enable_penetration_detection=True,
            enable_rate_limiting=False,
        ),
    )
    return app


async def _status(route: str | None) -> int:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(route), client=("203.0.113.41", 1)),
        base_url="http://testserver",
    ) as client:
        return (await client.get(PROBE)).status_code


async def test_a_decoy_registered_as_a_literal_route_is_clean() -> None:
    assert await _status(PROBE) == 404


async def test_a_probe_the_app_does_not_declare_is_flagged() -> None:
    assert await _status(None) == 400


@pytest.mark.parametrize("route", ["/{rest:path}", "/{page}"])
async def test_a_catch_all_or_converter_route_does_not_declare_the_probe(
    route: str,
) -> None:
    assert await _status(route) == 400
