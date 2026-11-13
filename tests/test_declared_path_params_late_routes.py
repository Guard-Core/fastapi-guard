"""A route added after startup is checked when the table changes, not when it is
first requested: one warning without fail_on_misconfiguration, a fresh refusal on
every request with it, and no whole-table walk while the table holds."""

import gc
import logging
import traceback
import weakref
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI
from guard_core.exceptions import MisconfigurationError
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Host, Mount, Route

from guard import SecurityDecorator, _declared_path_params
from tests.test_declared_path_params import (
    CLASSES,
    LOGGER,
    _app,
    _config,
    _get,
    _missing,
    _problems,
)
from tests.test_declared_path_params_flag import _get_raising

REFUSAL = "Every request is refused until this is fixed"


def _refusals(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if REFUSAL in r.getMessage()]


def _declare_ok(app: FastAPI, decorator: SecurityDecorator) -> None:
    @app.get("/ok")
    async def ok() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/other")
    async def other() -> dict[str, bool]:
        return {"other": True}


def _late_endpoint(decorator: SecurityDecorator, declared: str) -> Any:
    @decorator.detection_exclusion(path_params={declared})
    async def late(item_id: str) -> dict[str, str]:
        return {"item": item_id}

    return late


def _add_bad_route(target: Any, decorator: SecurityDecorator, path: str) -> None:
    target.add_api_route(path, _late_endpoint(decorator, "ghost"))


def _declared_ghost(decorator: SecurityDecorator) -> Any:
    @decorator.detection_exclusion(path_params={"ghost"})
    async def view(request: Any) -> JSONResponse:
        return JSONResponse({"ok": True})

    return view


def _add_good_route(target: Any, decorator: SecurityDecorator, path: str) -> None:
    target.add_api_route(path, _late_endpoint(decorator, "item_id"))


def _declare_ok_and_included(app: FastAPI, decorator: SecurityDecorator) -> None:
    _declare_ok(app, decorator)
    router = APIRouter(prefix="/inc")

    async def seed() -> dict[str, bool]:
        return {"seed": True}

    router.add_api_route("/seed", seed)
    app.state.late_router = router
    app.include_router(router)


def _target(app: FastAPI, variant: str) -> Any:
    return app.state.late_router if variant == "included" else app


VARIANTS = pytest.mark.parametrize("variant", ["app", "included"])


def _build(middleware_class: type, variant: str, **overrides: Any) -> FastAPI:
    declare = _declare_ok_and_included if variant == "included" else _declare_ok
    return _app(middleware_class, _config(**overrides), declare)


@CLASSES
@VARIANTS
async def test_l1_late_route_with_the_flag_off_warns_once_on_an_unrelated_request(
    middleware_class: type, variant: str, caplog: pytest.LogCaptureFixture
) -> None:
    app = _build(middleware_class, variant, fail_on_misconfiguration=False)
    caplog.set_level(logging.WARNING, logger=LOGGER)
    assert await _get(app, "/ok") == 200
    assert _problems(caplog) == []

    _add_bad_route(_target(app, variant), app.state.guard_decorator, "/late/{item_id}")
    assert await _get(app, "/ok") == 200
    assert await _get(app, "/other") == 200

    (problem,) = _problems(caplog)
    prefix = "/inc" if variant == "included" else ""
    assert _missing(f"{prefix}/late/{{item_id}}") in problem


@CLASSES
@VARIANTS
async def test_l1_late_route_with_the_flag_on_refuses_every_request_and_logs_once(
    middleware_class: type, variant: str, caplog: pytest.LogCaptureFixture
) -> None:
    app = _build(middleware_class, variant, fail_on_misconfiguration=True)
    caplog.set_level(logging.ERROR, logger=LOGGER)
    assert await _get_raising(app, "/ok") == 200

    _add_bad_route(_target(app, variant), app.state.guard_decorator, "/late/{item_id}")
    for path in ("/ok", "/other"):
        with pytest.raises(MisconfigurationError):
            await _get_raising(app, path)

    assert len(_refusals(caplog)) == 1


@CLASSES
@VARIANTS
async def test_l2_the_table_is_walked_once_per_change_and_never_per_request(
    middleware_class: type,
    variant: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _build(middleware_class, variant, fail_on_misconfiguration=False)
    assert await _get(app, "/ok") == 200
    assert await _get(app, "/ok") == 200
    walks: list[int] = []
    real = _declared_path_params.declared_path_param_problems

    def counting(*args: Any) -> Any:
        walks.append(1)
        return real(*args)

    monkeypatch.setattr(_declared_path_params, "declared_path_param_problems", counting)

    for _ in range(50):
        assert await _get(app, "/ok") == 200
    assert walks == []

    _add_good_route(_target(app, variant), app.state.guard_decorator, "/late/{item_id}")
    for _ in range(50):
        assert await _get(app, "/ok") == 200
    assert len(walks) == 1


@CLASSES
async def test_f_fresh_every_refusal_is_a_new_error_of_the_same_depth(
    middleware_class: type,
) -> None:
    app = _build(middleware_class, "app", fail_on_misconfiguration=True)
    assert await _get_raising(app, "/ok") == 200
    _add_bad_route(app, app.state.guard_decorator, "/late/{item_id}")

    errors: list[MisconfigurationError] = []
    for _ in range(3):
        with pytest.raises(MisconfigurationError) as refused:
            await _get_raising(app, "/ok")
        errors.append(refused.value)

    assert len({id(error) for error in errors}) == 3
    assert len({len(traceback.extract_tb(e.__traceback__)) for e in errors}) == 1


@CLASSES
@VARIANTS
async def test_g_a_late_route_with_a_correct_declaration_reports_nothing(
    middleware_class: type, variant: str, caplog: pytest.LogCaptureFixture
) -> None:
    app = _build(middleware_class, variant, fail_on_misconfiguration=True)
    caplog.set_level(logging.WARNING, logger=LOGGER)
    assert await _get_raising(app, "/ok") == 200

    _add_good_route(_target(app, variant), app.state.guard_decorator, "/late/{item_id}")

    assert await _get_raising(app, "/ok") == 200
    assert _problems(caplog) == []
    assert _refusals(caplog) == []


@CLASSES
async def test_g_a_late_route_in_a_mount_and_a_host_is_found(
    middleware_class: type, caplog: pytest.LogCaptureFixture
) -> None:
    app = _build(middleware_class, "app", fail_on_misconfiguration=False)
    caplog.set_level(logging.WARNING, logger=LOGGER)
    sub = Starlette(routes=[Route("/seed", lambda request: JSONResponse({}))])
    host_sub = Starlette(routes=[Route("/seed", lambda request: JSONResponse({}))])
    app.mount("/m", sub)
    app.router.routes.append(Host("example.test", host_sub))
    assert await _get(app, "/ok") == 200
    assert _problems(caplog) == []

    for router, path in ((sub.router, "/y/{item_id}"), (host_sub.router, "/z/{k}")):
        router.routes.append(Route(path, _declared_ghost(app.state.guard_decorator)))
    assert await _get(app, "/ok") == 200

    assert len(_problems(caplog)) == 2
    assert isinstance(app.routes[-2], Mount)


@CLASSES
async def test_g_leak_the_cache_does_not_keep_the_app_alive(
    middleware_class: type,
) -> None:
    app = _build(middleware_class, "included", fail_on_misconfiguration=False)
    assert await _get(app, "/ok") == 200
    assert await _get(app, "/ok") == 200
    reference = weakref.ref(app)

    del app
    gc.collect()

    assert reference() is None


def test_a_stored_layout_whose_index_is_past_its_parent_no_longer_holds() -> None:
    inner = [Route("/seed", lambda request: JSONResponse({}))]
    root: list[Any] = [Mount("/m", routes=inner)]
    layout = _declared_path_params._layout_of(root)
    assert _declared_path_params._layout_holds(root, layout) is True

    past_the_parent = (*layout, (1, len(inner), id(inner), 0))

    assert _declared_path_params._layout_holds(root, past_the_parent) is False
