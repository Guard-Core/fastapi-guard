from pathlib import Path

from guard_core.models import SecurityConfig
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Host, Mount, Route
from starlette.staticfiles import StaticFiles

from guard import SecurityMiddleware
from guard._route_gate_host import hold_route_gate_host, release_route_gate_host

HOST = "api.example.com"


async def _res(request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


def _engine(static_root: Path) -> SecurityMiddleware:
    sub = Starlette(
        routes=[
            Mount("/static", StaticFiles(directory=static_root)),
            Route("/res", _res, methods=["GET", "POST"]),
        ]
    )
    app = Starlette(routes=[Host(HOST, app=sub)])
    engine = SecurityMiddleware(
        app,
        config=SecurityConfig(
            enable_redis=False, enable_rate_limiting=False, trusted_proxies=[]
        ),
    )
    engine._routing_app = app
    return engine


async def test_the_gate_helpers_find_a_route_under_the_requests_host(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.js.map").write_text("{}")
    engine = _engine(tmp_path)

    token = hold_route_gate_host(HOST)
    try:
        served = await engine.static_file_exists("/static/app.js.map")
        methods = engine.allowed_methods("/res")
        identities = engine.resolve_route("/res")
    finally:
        release_route_gate_host(token)

    assert served is True
    assert methods == ("GET", "HEAD", "POST")
    assert len(identities) == 1


async def test_without_the_host_a_host_route_is_not_found(tmp_path: Path) -> None:
    (tmp_path / "app.js.map").write_text("{}")
    engine = _engine(tmp_path)

    assert await engine.static_file_exists("/static/app.js.map") is False
    assert engine.allowed_methods("/res") == ()
