import pytest
from fastapi import APIRouter, FastAPI
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from httpx import ASGITransport, AsyncClient
from starlette.middleware import Middleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.routing import Mount

from guard import SecurityConfig, SecurityDecorator
from guard.middleware import SecurityMiddleware

ATTACK_BODY = {"note": "<script>alert(1)</script>"}


def _config(**overrides: object) -> SecurityConfig:
    return SecurityConfig(
        enable_penetration_detection=True,
        enable_rate_limiting=False,
        enable_ip_banning=False,
        enable_redis=False,
        **overrides,  # type: ignore[arg-type]
    )


def _app(
    *,
    redirect_slashes: bool = True,
    mounted_redirect_slashes: bool = True,
    **overrides: object,
) -> FastAPI:
    config = _config(**overrides)
    decorator = SecurityDecorator(config)
    app = FastAPI(redirect_slashes=redirect_slashes)
    router = APIRouter(prefix="/api")
    mounted = FastAPI(redirect_slashes=mounted_redirect_slashes)
    wrapped = FastAPI(redirect_slashes=mounted_redirect_slashes)

    @app.post("/triggers/{trigger_id}")
    @decorator.bypass(["penetration"])
    async def trigger(trigger_id: str) -> dict[str, str]:
        return {"id": trigger_id}

    @app.post("/items/")
    @decorator.bypass(["penetration"])
    async def items() -> dict[str, bool]:
        return {"ok": True}

    @router.post("/things/{thing_id}")
    @decorator.bypass(["penetration"])
    async def thing(thing_id: str) -> dict[str, str]:
        return {"id": thing_id}

    @mounted.post("/deep/{deep_id}")
    @decorator.bypass(["penetration"])
    async def deep(deep_id: str) -> dict[str, str]:
        return {"id": deep_id}

    @wrapped.post("/deep/{deep_id}")
    @decorator.bypass(["penetration"])
    async def wrapped_deep(deep_id: str) -> dict[str, str]:
        return {"id": deep_id}

    app.include_router(router)
    app.mount("/sub", mounted)
    app.router.routes.append(
        Mount("/wrapped", app=wrapped, middleware=[Middleware(GZipMiddleware)])
    )
    app.add_middleware(SecurityMiddleware, config=config)
    app.state.guard_decorator = decorator
    return app


async def _post(app: FastAPI, path: str, body: dict[str, str]) -> tuple[int, str]:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(path, json=body)
    return response.status_code, response.headers.get("location", "")


@pytest.mark.parametrize(
    ("path", "redirect_to"),
    [
        ("/triggers/abc/", "/triggers/abc"),
        ("/items", "/items/"),
        ("/api/things/1/", "/api/things/1"),
        ("/sub/deep/1/", "/sub/deep/1"),
        ("/wrapped/deep/1/", "/wrapped/deep/1"),
    ],
)
async def test_other_slash_form_gets_the_route_config(
    path: str, redirect_to: str
) -> None:
    app = _app()

    assert await _post(app, redirect_to, ATTACK_BODY) == (200, "")
    assert await _post(app, path, ATTACK_BODY) == (307, f"http://test{redirect_to}")


async def test_path_without_a_route_in_either_form_keeps_the_global_checks() -> None:
    assert await _post(_app(), "/missing/", ATTACK_BODY) == (400, "")


@pytest.mark.parametrize(
    ("redirect_slashes", "mounted_redirect_slashes", "path", "expected"),
    [
        (False, True, "/triggers/abc/", (400, "")),
        (False, True, "/api/things/1/", (400, "")),
        (False, True, "/sub/deep/1/", (307, "http://test/sub/deep/1")),
        (True, False, "/sub/deep/1/", (400, "")),
        (True, False, "/wrapped/deep/1/", (400, "")),
    ],
)
async def test_each_router_decides_with_its_own_redirect_slashes(
    redirect_slashes: bool,
    mounted_redirect_slashes: bool,
    path: str,
    expected: tuple[int, str],
) -> None:
    app = _app(
        redirect_slashes=redirect_slashes,
        mounted_redirect_slashes=mounted_redirect_slashes,
    )

    assert await _post(app, path, ATTACK_BODY) == expected


# guard-core 4.5.0 answers 404 for a path no route serves under strict resolution;
# 4.4.0 answered 500. The marker is the per-middleware headers manager of 4.5.0.
_UNSERVED_PATH_STATUS = 404 if hasattr(SecurityHeadersManager, "isolated") else 500


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/triggers/abc/", (307, "http://test/triggers/abc")),
        ("/missing/", (_UNSERVED_PATH_STATUS, "")),
    ],
)
async def test_strict_route_resolution_accepts_the_other_slash_form(
    path: str, expected: tuple[int, str]
) -> None:
    app = _app(route_resolution_strict=True)

    assert await _post(app, path, {"note": "hello"}) == expected
