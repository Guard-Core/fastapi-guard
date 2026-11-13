"""fail_on_misconfiguration governs the first-request report of a declared
detection_exclusion path param, with or without lifespan wiring."""

import logging
from typing import Any

import pytest
from fastapi import FastAPI
from guard_core._misconfiguration_kinds import MisconfigurationError
from httpx import ASGITransport, AsyncClient

from guard import SecurityDecorator
from guard.asgi import PureASGISecurityMiddleware
from guard.middleware import SecurityMiddleware
from tests.test_declared_path_params import (
    CLASSES,
    LOGGER,
    _app,
    _config,
    _get,
    _missing,
    _problems,
    declare_missing,
    declare_rootless,
)


async def _get_raising(app: FastAPI, path: str) -> int:
    async with AsyncClient(
        transport=ASGITransport(app, client=("203.0.113.9", 4321)),
        base_url="http://t",
    ) as client:
        return (await client.get(path)).status_code


@CLASSES
@pytest.mark.parametrize(
    ("declare", "path"), [(declare_missing, "/items/7"), (declare_rootless, "/x")]
)
async def test_with_the_flag_on_the_first_request_refuses_instead_of_warning(
    middleware_class: type, declare: Any, path: str
) -> None:
    app = _app(middleware_class, _config(fail_on_misconfiguration=True), declare)

    with pytest.raises(MisconfigurationError) as refused:
        await _get_raising(app, path)

    assert "@detection_exclusion(path_params=...)" in str(refused.value)


@CLASSES
async def test_with_the_flag_on_every_request_refuses_until_it_is_fixed(
    middleware_class: type,
) -> None:
    app = _app(
        middleware_class, _config(fail_on_misconfiguration=True), declare_missing
    )

    for _ in range(2):
        with pytest.raises(MisconfigurationError):
            await _get_raising(app, "/items/7")


@CLASSES
async def test_the_refusal_carries_the_kind_and_the_declared_name(
    middleware_class: type,
) -> None:
    app = _app(
        middleware_class, _config(fail_on_misconfiguration=True), declare_missing
    )

    with pytest.raises(MisconfigurationError) as refused:
        await _get_raising(app, "/items/7")

    assert [(p.kind, p.subject) for p in refused.value.problems] == [
        ("decorator.detection_exclusion.param_not_in_template", "ghost")
    ]


@CLASSES
async def test_with_the_flag_off_one_warning_carries_its_kind_and_the_request_is_served(
    middleware_class: type, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(
        middleware_class, _config(fail_on_misconfiguration=False), declare_missing
    )
    caplog.set_level(logging.WARNING, logger=LOGGER)

    assert await _get(app, "/items/7") == 200
    assert await _get(app, "/items/7") == 200

    (problem,) = _problems(caplog)
    assert _missing("/items/{item_id:int}") in problem
    carried = [
        r.__dict__["problems"] for r in caplog.records if "problems" in r.__dict__
    ]
    assert (
        ("decorator.detection_exclusion.param_not_in_template", "ghost"),
    ) in carried


def test_the_adapter_holds_no_copy_of_the_engine_text() -> None:
    import pathlib

    import guard

    root = pathlib.Path(guard.__file__).parent
    assert not [
        p.name
        for p in root.rglob("*.py")
        if "@detection_exclusion(path_params=...) on route" in p.read_text()
    ]


_ = (SecurityDecorator, SecurityMiddleware, PureASGISecurityMiddleware)
