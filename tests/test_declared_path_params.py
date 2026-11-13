"""LEDGER 6.851: a declared detection_exclusion path param the route does not have
is reported at the lifespan warm and at the lazy first-request init: a raise with
fail_on_misconfiguration, one WARNING without it."""

import logging
from collections.abc import Callable
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI
from guard_core.models import SecurityConfig
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import BaseRoute, Host, Match, Route

from guard import SecurityDecorator
from guard.asgi import PureASGISecurityMiddleware
from guard.lifespan import make_lifespan
from guard.middleware import SecurityMiddleware
from tests.test_lifespan_auto_warm import Lifespan, started

CLASSES = pytest.mark.parametrize(
    "middleware_class",
    [SecurityMiddleware, PureASGISecurityMiddleware],
    ids=["classic", "pure"],
)
LOGGER = "guard_core.models"
Declare = Callable[[FastAPI, SecurityDecorator], None]


def _missing(template: str, name: str = "ghost") -> str:
    return (
        f"declares {name!r}, which is not in the route template {template!r}, so it "
        "exempts nothing."
    )


def _rootless(template: str, name: str = "tail") -> str:
    return (
        f"declares {name!r}, which has no literal segment before it in the route "
        f"template {template!r}: it would exempt the whole path from the probe rows, "
        "so the whole path is scanned."
    )


def _app(middleware_class: Any, config: SecurityConfig, declare: Declare) -> FastAPI:
    app = FastAPI()
    decorator = SecurityDecorator(config)
    app.state.guard_decorator = decorator
    declare(app, decorator)
    app.add_middleware(middleware_class, config=config)
    return app


def _config(**overrides: Any) -> SecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "custom_log_file": "test_log.log",
    }
    settings.update(overrides)
    return SecurityConfig(**settings)


def declare_missing(app: FastAPI, decorator: SecurityDecorator) -> None:
    @decorator.detection_exclusion(path_params={"ghost"})
    @app.get("/items/{item_id:int}")
    async def item(item_id: int) -> dict[str, int]:
        return {"item": item_id}


def declare_rootless(app: FastAPI, decorator: SecurityDecorator) -> None:
    @decorator.detection_exclusion(path_params={"tail"})
    @app.get("/{tail:path}")
    async def catch_all(tail: str) -> dict[str, str]:
        return {"tail": tail}


def declare_valid(app: FastAPI, decorator: SecurityDecorator) -> None:
    @decorator.detection_exclusion(path_params={"item_id"})
    @app.get("/items/{item_id:int}")
    async def item(item_id: int) -> dict[str, int]:
        return {"item": item_id}


def declare_unguarded_and_empty(app: FastAPI, decorator: SecurityDecorator) -> None:
    @app.get("/plain/{x}")
    async def plain(x: str) -> dict[str, str]:
        return {"x": x}

    @decorator.detection_exclusion(headers={"x-trace"})
    @app.get("/headers/{y}")
    async def headers(y: str) -> dict[str, str]:
        return {"y": y}


def declare_in_included_routers(app: FastAPI, decorator: SecurityDecorator) -> None:
    inner = APIRouter(prefix="/inner")
    outer = APIRouter(prefix="/outer")

    @decorator.detection_exclusion(path_params={"ghost"})
    @inner.get("/things/{thing_id}")
    async def thing(thing_id: str) -> dict[str, str]:
        return {"thing": thing_id}

    outer.include_router(inner, prefix="/deep")
    app.include_router(outer, prefix="/v1")


def declare_in_a_mount(app: FastAPI, decorator: SecurityDecorator) -> None:
    @decorator.detection_exclusion(path_params={"ghost"})
    async def view(request: Any) -> JSONResponse:
        return JSONResponse({"ok": True})

    app.mount("/m", Starlette(routes=[Route("/y/{k}", view)]))


def declare_in_a_host_and_beside_a_route_without_an_endpoint(
    app: FastAPI, decorator: SecurityDecorator
) -> None:
    class Endpointless(BaseRoute):
        def matches(self, scope: Any) -> tuple[Match, Any]:
            return Match.NONE, {}

        async def handle(self, scope: Any, receive: Any, send: Any) -> None:
            return None

    @decorator.detection_exclusion(path_params={"ghost"})
    async def view(request: Any) -> JSONResponse:
        return JSONResponse({"ok": True})

    app.router.routes.append(Endpointless())
    app.router.routes.append(
        Host("example.test", Starlette(routes=[Route("/y/{k}", view)]))
    )


def declare_one_view_on_two_routes(app: FastAPI, decorator: SecurityDecorator) -> None:
    @decorator.detection_exclusion(path_params={"ghost"})
    @app.get("/a/{x}")
    @app.get("/b/{y}")
    async def view(x: str = "", y: str = "") -> dict[str, str]:
        return {}


def _problems(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == LOGGER and "@detection_exclusion" in r.getMessage()
    ]


async def _get(app: FastAPI, path: str) -> int:
    async with AsyncClient(
        transport=ASGITransport(app, client=("203.0.113.9", 4321)),
        base_url="http://t",
    ) as client:
        return (await client.get(path)).status_code


@CLASSES
@pytest.mark.parametrize("declare", [declare_missing, declare_rootless])
async def test_a_problem_stops_the_boot_with_the_flag_on(
    middleware_class: type, declare: Declare
) -> None:
    app = _app(middleware_class, _config(fail_on_misconfiguration=True), declare)

    lifespan = Lifespan(app)
    assert await lifespan.start() == "lifespan.startup.failed"
    await lifespan.stop()


@CLASSES
@pytest.mark.parametrize(
    ("declare", "tail"),
    [
        (declare_missing, _missing("/items/{item_id:int}")),
        (declare_rootless, _rootless("/{tail:path}")),
        (
            declare_in_included_routers,
            _missing("/v1/outer/deep/inner/things/{thing_id}"),
        ),
        (declare_in_a_mount, _missing("/m/y/{k}")),
        (declare_in_a_host_and_beside_a_route_without_an_endpoint, _missing("/y/{k}")),
    ],
)
async def test_a_problem_warns_at_the_boot_with_the_flag_off(
    middleware_class: type,
    declare: Declare,
    tail: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app(middleware_class, _config(fail_on_misconfiguration=False), declare)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    async with started(app):
        pass

    (problem,) = _problems(caplog)
    assert tail in problem
    assert "fail_on_misconfiguration=False keeps starting with it." in problem


@CLASSES
async def test_one_view_on_two_routes_is_checked_per_route(
    middleware_class: type, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(
        middleware_class,
        _config(fail_on_misconfiguration=False),
        declare_one_view_on_two_routes,
    )
    caplog.set_level(logging.WARNING, logger=LOGGER)

    async with started(app):
        pass

    problems = _problems(caplog)
    assert len(problems) == 2
    assert any(_missing("/a/{x}") in problem for problem in problems)
    assert any(_missing("/b/{y}") in problem for problem in problems)


@CLASSES
@pytest.mark.parametrize("declare", [declare_valid, declare_unguarded_and_empty])
async def test_a_sound_declaration_reports_nothing(
    middleware_class: type, declare: Declare, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(middleware_class, _config(fail_on_misconfiguration=True), declare)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    async with started(app):
        pass

    assert _problems(caplog) == []


@CLASSES
@pytest.mark.parametrize(
    ("declare", "path", "tail"),
    [
        (declare_missing, "/items/7", _missing("/items/{item_id:int}")),
        (declare_rootless, "/anything", _rootless("/{tail:path}")),
    ],
)
async def test_the_lazy_first_request_warns_once_with_the_flag_off(
    middleware_class: type,
    declare: Declare,
    path: str,
    tail: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app(middleware_class, _config(fail_on_misconfiguration=False), declare)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    assert await _get(app, path) == 200
    assert await _get(app, path) == 200

    (problem,) = _problems(caplog)
    assert tail in problem


async def test_make_lifespan_stops_the_boot_too() -> None:
    config = _config(fail_on_misconfiguration=True)
    app = FastAPI(lifespan=make_lifespan())
    decorator = SecurityDecorator(config)
    app.state.guard_decorator = decorator
    declare_missing(app, decorator)
    app.add_middleware(SecurityMiddleware, config=config)

    lifespan = Lifespan(app)
    assert await lifespan.start() == "lifespan.startup.failed"
    await lifespan.stop()
