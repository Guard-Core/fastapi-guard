"""Response headers stay a list of pairs on both middlewares."""

import itertools
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import Response
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from httpx import ASGITransport, AsyncClient

from guard import (
    PureASGISecurityMiddleware,
    SecurityConfig,
    SecurityDecorator,
    SecurityMiddleware,
)

requires_engine_with_isolated_headers = pytest.mark.skipif(
    not hasattr(SecurityHeadersManager, "isolated"),
    reason="needs a guard-core whose security headers follow the app and the config",
)

_IP = itertools.count(1)
_MIDDLEWARES = [SecurityMiddleware, PureASGISecurityMiddleware]
_ORIGIN = "https://app.example"


def _unique_ip() -> str:
    n = next(_IP)
    return f"198.19.{n // 250}.{(n % 250) + 1}"


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {"enable_redis": False, "enable_rate_limiting": False}
    fields.update(overrides)
    return SecurityConfig(**fields)


def _repeated(response: Response) -> Response:
    response.headers.append("set-cookie", "a=1; Path=/")
    response.headers.append("set-cookie", "b=2; Path=/")
    response.headers.append("link", "</x>; rel=preload")
    response.headers.append("link", "</y>; rel=preload")
    return response


def _app(middleware: Any, config: SecurityConfig) -> FastAPI:
    app = FastAPI()
    guard = SecurityDecorator(config)
    app.state.guard_decorator = guard
    app.add_middleware(middleware, config=config)

    @app.get("/c")
    async def repeated() -> Response:
        response = _repeated(Response("ok"))
        response.headers["x-frame-options"] = "DENY"
        return response

    @app.get("/vary")
    async def vary() -> Response:
        response = Response("ok")
        response.headers["vary"] = "Accept-Encoding"
        return response

    @app.get("/plain")
    async def plain() -> Response:
        return Response("ok")

    @app.get("/csp")
    async def csp() -> Response:
        response = Response("ok")
        response.headers["content-security-policy"] = "default-src *"
        return response

    @app.get("/bypass")
    @guard.bypass(["all"])
    async def bypass() -> Response:
        return _repeated(Response("ok"))

    return app


async def _get(
    middleware: Any, config: SecurityConfig, path: str, **headers: str
) -> httpx.Response:
    transport = ASGITransport(app=_app(middleware, config), client=(_unique_ip(), 5))
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.get(path, headers=headers)


def _values(response: httpx.Response, name: str) -> list[str]:
    return [v for k, v in response.headers.multi_items() if k.lower() == name]


_CONFIGS = {
    "headers-on": {},
    "headers-off-dict": {"security_headers": {"enabled": False}},
    "headers-off-none": {"security_headers": None},
    "cors-on": {"enable_cors": True, "cors_allow_origins": [_ORIGIN]},
}


@pytest.mark.parametrize("middleware", _MIDDLEWARES)
@pytest.mark.parametrize("config", _CONFIGS.values(), ids=_CONFIGS.keys())
async def test_repeated_set_cookie_and_link_survive(
    middleware: Any, config: dict[str, Any]
) -> None:
    response = await _get(middleware, _config(**config), "/c", origin=_ORIGIN)

    assert _values(response, "set-cookie") == ["a=1; Path=/", "b=2; Path=/"]
    assert _values(response, "link") == ["</x>; rel=preload", "</y>; rel=preload"]


@pytest.mark.parametrize("middleware", _MIDDLEWARES)
async def test_security_headers_off_adds_none_and_keeps_the_pairs(
    middleware: Any,
) -> None:
    response = await _get(
        middleware, _config(security_headers={"enabled": False}), "/c"
    )

    assert _values(response, "x-content-type-options") == []
    assert _values(response, "x-frame-options") == ["DENY"]


@pytest.mark.parametrize(
    "middleware",
    [
        pytest.param(SecurityMiddleware, marks=requires_engine_with_isolated_headers),
        PureASGISecurityMiddleware,
    ],
)
async def test_the_apps_header_is_never_duplicated_by_a_default(
    middleware: Any,
) -> None:
    response = await _get(middleware, _config(), "/c")

    assert _values(response, "x-frame-options") == ["DENY"]
    assert _values(response, "x-content-type-options") == ["nosniff"]


@pytest.mark.parametrize("middleware", _MIDDLEWARES)
async def test_the_apps_headers_keep_their_order_and_guards_come_after(
    middleware: Any,
) -> None:
    response = await _get(middleware, _config(), "/c")

    names = [k.lower() for k, _ in response.headers.multi_items()]
    app_part = [n for n in names if n in {"set-cookie", "link", "x-frame-options"}]
    assert app_part == ["set-cookie", "set-cookie", "link", "link", "x-frame-options"]
    assert names.index("x-content-type-options") > names.index("x-frame-options")


@pytest.mark.parametrize("middleware", _MIDDLEWARES)
async def test_vary_merges_with_the_apps_vary_for_an_allowed_origin(
    middleware: Any,
) -> None:
    config = _config(enable_cors=True, cors_allow_origins=[_ORIGIN])

    response = await _get(middleware, config, "/vary", origin=_ORIGIN)

    assert _values(response, "vary") == ["Accept-Encoding, Origin"]
    assert response.headers["access-control-allow-origin"] == _ORIGIN


@requires_engine_with_isolated_headers
@pytest.mark.parametrize("middleware", _MIDDLEWARES)
async def test_vary_origin_is_on_a_response_without_an_origin(middleware: Any) -> None:
    config = _config(enable_cors=True, cors_allow_origins=[_ORIGIN])

    with_app_vary = await _get(middleware, config, "/vary")
    without = await _get(middleware, config, "/plain", origin="https://evil.example")

    assert _values(with_app_vary, "vary") == ["Accept-Encoding, Origin"]
    assert _values(without, "vary") == ["Origin"]
    assert "access-control-allow-origin" not in without.headers


@requires_engine_with_isolated_headers
@pytest.mark.parametrize("middleware", _MIDDLEWARES)
async def test_a_configured_csp_replaces_the_apps(middleware: Any) -> None:
    config = _config(
        security_headers={"enabled": True, "csp": {"default-src": ["'self'"]}}
    )

    response = await _get(middleware, config, "/csp")

    assert _values(response, "content-security-policy") == ["default-src 'self'"]


@requires_engine_with_isolated_headers
@pytest.mark.parametrize("middleware", _MIDDLEWARES)
async def test_a_bypass_all_route_carries_the_security_headers_and_its_pairs(
    middleware: Any,
) -> None:
    response = await _get(middleware, _config(), "/bypass")

    assert _values(response, "set-cookie") == ["a=1; Path=/", "b=2; Path=/"]
    assert _values(response, "x-content-type-options") == ["nosniff"]


async def _modifier(response: Any) -> Any:
    return response


@requires_engine_with_isolated_headers
async def test_a_streamed_bypass_all_route_carries_the_security_headers() -> None:
    config = _config(custom_response_modifier=_modifier)

    response = await _get(PureASGISecurityMiddleware, config, "/bypass")

    assert _values(response, "set-cookie") == ["a=1; Path=/", "b=2; Path=/"]
    assert _values(response, "x-content-type-options") == ["nosniff"]


@requires_engine_with_isolated_headers
@pytest.mark.parametrize("middleware", _MIDDLEWARES)
async def test_a_blocked_response_carries_the_security_headers(
    middleware: Any,
) -> None:
    config = _config(blacklist=("198.19.250.1",))
    transport = ASGITransport(app=_app(middleware, config), client=("198.19.250.1", 5))
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/plain")

    assert response.status_code == 403
    assert _values(response, "x-content-type-options") == ["nosniff"]
