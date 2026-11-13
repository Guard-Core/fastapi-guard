"""A route stamped by a SecurityDecorator other than the one the middleware uses is
reported at startup and when requested, and a mounted app that runs its own guard
middleware is left to that middleware."""

import logging
from collections.abc import Callable
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI
from guard_core._utils.route_gate import route_unknown_to_decorator_problem
from guard_core.exceptions import MisconfigurationError
from guard_core.models import SecurityConfig
from httpx import ASGITransport, AsyncClient
from starlette.middleware import Middleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.routing import Host, Mount

from guard import SecurityDecorator
from guard._declared_path_params import declared_path_param_problems
from guard._owned_mounts import owns_its_routes
from guard.asgi import PureASGISecurityMiddleware
from guard.middleware import SecurityMiddleware
from tests.test_lifespan_auto_warm import Lifespan, started

CLASSES = pytest.mark.parametrize(
    "middleware_class",
    [SecurityMiddleware, PureASGISecurityMiddleware],
    ids=["classic", "pure"],
)
KIND = route_unknown_to_decorator_problem("x").kind
NEED = {"X-Need": "1"}


def _config(**overrides: Any) -> SecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "custom_log_file": "test_log.log",
    }
    settings.update(overrides)
    return SecurityConfig(**settings)


def _router(decorator: SecurityDecorator | None) -> APIRouter:
    router = APIRouter()
    if decorator is None:

        @router.get("/admin/")
        async def open_admin() -> dict[str, str]:
            return {"admin": "reached"}

        return router

    @router.get("/admin/")
    @decorator.require_headers({"X-Need": "required"})
    async def admin() -> dict[str, str]:
        return {"admin": "reached"}

    return router


def _root(
    middleware_class: Any, config: SecurityConfig
) -> tuple[FastAPI, SecurityDecorator]:
    app = FastAPI()
    root_decorator = SecurityDecorator(config)
    app.state.guard_decorator = root_decorator
    app.add_middleware(middleware_class, config=config)

    @app.get("/hello/")
    @root_decorator.require_headers({"X-Root": "required"})
    async def hello() -> dict[str, str]:
        return {"ok": "hello"}

    return app, root_decorator


def _sub_with_own_guard(
    middleware_class: Any, decorator_of: Callable[[SecurityConfig], SecurityDecorator]
) -> FastAPI:
    sub = FastAPI()
    sub_config = _config()
    sub_decorator = decorator_of(sub_config)
    sub.state.guard_decorator = sub_decorator
    sub.add_middleware(middleware_class, config=sub_config)
    sub.include_router(_router(sub_decorator))
    return sub


def _foreign(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if any(kind == KIND for kind, _ in r.__dict__.get("problems", ()))
    ]


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


async def _get(app: FastAPI, path: str, **kw: Any) -> int:
    async with AsyncClient(
        transport=ASGITransport(
            app, raise_app_exceptions=False, client=("203.0.113.9", 4321)
        ),
        base_url="http://t",
    ) as client:
        return (await client.get(path, **kw)).status_code


@CLASSES
async def test_a_foreign_route_is_refused_by_default_and_a_root_route_is_not(
    middleware_class: Any,
) -> None:
    app, _ = _root(middleware_class, _config(fail_on_misconfiguration=True))
    app.include_router(_router(SecurityDecorator(_config())), prefix="/pkg")

    assert await _get(app, "/pkg/admin/", headers=NEED) == 500
    assert await _get(app, "/hello/", headers={"X-Root": "1"}) == 500
    with pytest.raises(MisconfigurationError) as refused:
        async with AsyncClient(
            transport=ASGITransport(app, client=("203.0.113.9", 4321)),
            base_url="http://t",
        ) as client:
            await client.get("/pkg/admin/", headers=NEED)
    assert [p.kind for p in refused.value.problems] == [KIND]


@CLASSES
async def test_a_foreign_route_stops_the_boot_with_the_flag_on(
    middleware_class: Any,
) -> None:
    app, _ = _root(middleware_class, _config(fail_on_misconfiguration=True))
    app.include_router(_router(SecurityDecorator(_config())), prefix="/pkg")

    assert await Lifespan(app).start() == "lifespan.startup.failed"


@CLASSES
async def test_a_foreign_route_is_served_and_reported_once_with_the_flag_off(
    middleware_class: Any, caplog: pytest.LogCaptureFixture
) -> None:
    app, _ = _root(middleware_class, _config(fail_on_misconfiguration=False))
    app.include_router(_router(SecurityDecorator(_config())), prefix="/pkg")
    caplog.set_level(logging.WARNING)

    async with started(app):
        statuses = [await _get(app, "/pkg/admin/", headers=NEED) for _ in range(3)]

    assert statuses == [200, 200, 200]
    (record,) = _foreign(caplog)
    label = record.__dict__["problems"][0][1]
    assert str(route_unknown_to_decorator_problem(label)) in record.getMessage()


@CLASSES
async def test_the_root_route_is_unaffected_by_a_foreign_one(
    middleware_class: Any,
) -> None:
    app, _ = _root(middleware_class, _config(fail_on_misconfiguration=False))
    app.include_router(_router(SecurityDecorator(_config())), prefix="/pkg")

    assert await _get(app, "/hello/") == 400
    assert await _get(app, "/hello/", headers={"X-Root": "1"}) == 200


@CLASSES
async def test_a_package_sharing_the_root_decorator_is_not_reported(
    middleware_class: Any, caplog: pytest.LogCaptureFixture
) -> None:
    app, root_decorator = _root(middleware_class, _config())
    app.include_router(_router(root_decorator), prefix="/pkg")
    caplog.set_level(logging.WARNING)

    assert await _get(app, "/pkg/admin/", headers=NEED) == 200
    assert await _get(app, "/pkg/admin/") == 400
    assert _foreign(caplog) == []


@CLASSES
async def test_a_decorator_created_and_never_used_is_not_reported(
    middleware_class: Any, caplog: pytest.LogCaptureFixture
) -> None:
    app, _ = _root(middleware_class, _config())
    SecurityDecorator(_config())
    app.include_router(_router(None), prefix="/pkg")
    caplog.set_level(logging.WARNING)

    assert await _get(app, "/pkg/admin/") == 200
    assert _foreign(caplog) == []


@CLASSES
@pytest.mark.parametrize(
    "mounted_guard", [SecurityMiddleware, PureASGISecurityMiddleware]
)
async def test_a_mount_with_its_own_guard_is_not_reported_and_is_enforced_inside(
    middleware_class: Any,
    mounted_guard: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    app, _ = _root(middleware_class, _config(fail_on_misconfiguration=True))
    app.mount("/sub", _sub_with_own_guard(mounted_guard, SecurityDecorator))
    caplog.set_level(logging.WARNING)

    async with started(app):
        assert await _get(app, "/sub/admin/") == 400
        assert await _get(app, "/sub/admin/", headers=NEED) == 200
    assert _foreign(caplog) == []
    assert [w for w in _warnings(caplog) if "SecurityDecorator" in w] == []


@CLASSES
async def test_a_mounted_pure_asgi_wrapper_is_not_reported(
    middleware_class: Any, caplog: pytest.LogCaptureFixture
) -> None:
    app, _ = _root(middleware_class, _config(fail_on_misconfiguration=True))
    sub = FastAPI()
    sub_config = _config()
    sub_decorator = SecurityDecorator(sub_config)
    sub.state.guard_decorator = sub_decorator
    sub.include_router(_router(sub_decorator))
    wrapped = PureASGISecurityMiddleware(sub, config=sub_config)
    app.mount("/sub", wrapped)
    caplog.set_level(logging.WARNING)

    assert await _get(app, "/hello/", headers={"X-Root": "1"}) == 200
    assert _foreign(caplog) == []


@CLASSES
async def test_a_mount_with_no_guard_of_its_own_is_reported(
    middleware_class: Any, caplog: pytest.LogCaptureFixture
) -> None:
    app, _ = _root(middleware_class, _config(fail_on_misconfiguration=False))
    sub = FastAPI()
    sub.include_router(_router(SecurityDecorator(_config())))
    app.mount("/sub", sub)
    caplog.set_level(logging.WARNING)

    assert await _get(app, "/sub/admin/", headers=NEED) == 200
    assert len(_foreign(caplog)) == 1


async def test_a_mount_with_no_guard_of_its_own_is_refused_with_the_flag_on() -> None:
    app, _ = _root(SecurityMiddleware, _config(fail_on_misconfiguration=True))
    sub = FastAPI()
    sub.include_router(_router(SecurityDecorator(_config())))
    app.mount("/sub", sub)

    assert await _get(app, "/sub/admin/", headers=NEED) == 500


async def test_a_host_with_its_own_guard_is_not_reported(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app, _ = _root(SecurityMiddleware, _config(fail_on_misconfiguration=True))
    app.router.routes.append(
        Host("sub.example", _sub_with_own_guard(SecurityMiddleware, SecurityDecorator))
    )
    caplog.set_level(logging.WARNING)

    assert await _get(app, "/hello/", headers={"X-Root": "1"}) == 200
    assert _foreign(caplog) == []


async def test_an_owned_mount_sharing_the_root_is_enforced_by_its_own_guard() -> None:
    app, root_decorator = _root(
        SecurityMiddleware, _config(fail_on_misconfiguration=True)
    )
    app.mount(
        "/sub", _sub_with_own_guard(SecurityMiddleware, lambda config: root_decorator)
    )

    assert await _get(app, "/sub/admin/") == 400
    assert await _get(app, "/sub/admin/", headers=NEED) == 200


def test_the_walk_skips_an_owned_mount_and_keeps_a_plain_one() -> None:
    owned_app, owned_decorator = _root(SecurityMiddleware, _config())
    owned_app.mount(
        "/owned", _sub_with_own_guard(SecurityMiddleware, SecurityDecorator)
    )
    plain_app, plain_decorator = _root(SecurityMiddleware, _config())
    plain = FastAPI()
    plain.include_router(_router(SecurityDecorator(_config())))
    plain_app.mount("/plain", plain)

    assert declared_path_param_problems(owned_app, owned_decorator) == []
    assert [
        p.kind for p in declared_path_param_problems(plain_app, plain_decorator)
    ] == [KIND]


async def test_an_owned_mount_sharing_the_root_limits_a_route_at_the_same_request() -> (
    None
):
    config = _config(fail_on_misconfiguration=False, rate_limit=1000)
    app, root_decorator = _root(SecurityMiddleware, config)
    sub = FastAPI()
    sub.state.guard_decorator = root_decorator
    sub.add_middleware(SecurityMiddleware, config=_config(rate_limit=1000))

    @sub.get("/limited/")
    @root_decorator.rate_limit(requests=3, window=60)
    async def limited() -> dict[str, int]:
        return {"ok": 1}

    app.mount("/sub", sub)

    statuses = [await _get(app, "/sub/limited/") for _ in range(5)]

    assert statuses == [200, 200, 200, 429, 429]


@pytest.mark.parametrize("guard", [SecurityMiddleware, PureASGISecurityMiddleware])
def test_a_mount_given_a_guard_as_its_middleware_is_left_to_it(guard: Any) -> None:
    app, root_decorator = _root(SecurityMiddleware, _config())
    sub = FastAPI()
    sub.include_router(_router(SecurityDecorator(_config())))
    app.router.routes.append(
        Mount(
            "/sub",
            app=sub,
            middleware=[
                Middleware(GZipMiddleware),
                Middleware(guard, config=_config()),
            ],
        )
    )

    assert declared_path_param_problems(app, root_decorator) == []


def test_one_foreign_handler_on_two_paths_is_reported_once() -> None:
    app, root_decorator = _root(SecurityMiddleware, _config())
    other = SecurityDecorator(_config())

    @app.get("/a/")
    @app.get("/b/")
    @other.require_headers({"X-Need": "required"})
    async def both() -> dict[str, str]:
        return {"ok": "both"}

    assert [p.kind for p in declared_path_param_problems(app, root_decorator)] == [KIND]


class _GuardSubclass(SecurityMiddleware):
    pass


def test_a_mount_registering_a_subclass_of_the_guard_is_left_to_it() -> None:
    app, root_decorator = _root(SecurityMiddleware, _config())
    sub = _sub_with_own_guard(_GuardSubclass, SecurityDecorator)
    app.mount("/sub", sub)

    assert declared_path_param_problems(app, root_decorator) == []


async def test_an_owned_mount_whose_guard_has_no_decorator_enforces_the_roots() -> None:
    app, root_decorator = _root(
        SecurityMiddleware, _config(fail_on_misconfiguration=False)
    )
    sub = FastAPI()
    sub.add_middleware(SecurityMiddleware, config=_config())

    @sub.get("/admin/")
    @root_decorator.require_headers({"X-Need": "required"})
    async def admin() -> dict[str, str]:
        return {"admin": "reached"}

    app.mount("/sub", sub)

    assert await _get(app, "/sub/admin/") == 400
    assert await _get(app, "/sub/admin/", headers=NEED) == 200


class _AppIsItself:
    """A wrapper whose ``app`` is itself, counting how often the walk reads it."""

    reads = 0

    @property
    def app(self) -> "_AppIsItself":
        type(self).reads += 1
        assert type(self).reads < 20, "the walk did not stop at a node it had seen"
        return self

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        return None


def test_a_wrapper_chain_that_loops_ends_the_walk() -> None:
    _AppIsItself.reads = 0
    mount = Mount("/loop", app=_AppIsItself())

    assert owns_its_routes(mount) is False
