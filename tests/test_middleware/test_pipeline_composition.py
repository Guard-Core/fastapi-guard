from unittest.mock import Mock

from fastapi import FastAPI
from starlette.requests import Request

from guard import SecurityConfig, SecurityDecorator
from guard.middleware import SecurityMiddleware

ROUTE_DRIVEN_CHECKS = {
    "authentication",
    "referrer",
    "time_window",
    "required_headers",
    "custom_validators",
    "request_size_content",
}


def _request_scoped_to(app: FastAPI) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/rate-limited",
            "query_string": b"",
            "headers": [],
            "server": ("localhost", 8000),
            "root_path": "",
            "state": {},
            "app": app,
        }
    )


async def test_app_state_decorator_drops_route_driven_checks_not_used() -> None:
    app = FastAPI()
    config = SecurityConfig(enable_redis=False)
    decorator = SecurityDecorator(config)

    @decorator.rate_limit(requests=10, window=60)
    @app.get("/rate-limited")
    async def rate_limited_endpoint() -> dict[str, str]:
        return {"message": "ok"}

    app.state.guard_decorator = decorator
    middleware = SecurityMiddleware(app, config=config)

    await middleware._ensure_initialized(_request_scoped_to(app))

    assert middleware.security_pipeline is not None
    check_names = set(middleware.security_pipeline.get_check_names())
    assert check_names.isdisjoint(ROUTE_DRIVEN_CHECKS)
    assert "rate_limit" in check_names


async def test_ensure_initialized_without_request_skips_adoption() -> None:
    app = FastAPI()
    config = SecurityConfig(enable_redis=False)
    decorator = SecurityDecorator(config)

    @decorator.rate_limit(requests=10, window=60)
    @app.get("/rate-limited")
    async def rate_limited_endpoint() -> dict[str, str]:
        return {"message": "ok"}

    app.state.guard_decorator = decorator
    middleware = SecurityMiddleware(app, config=config)

    await middleware._ensure_initialized()

    assert middleware.guard_decorator is None
    assert middleware.security_pipeline is not None
    check_names = set(middleware.security_pipeline.get_check_names())
    assert ROUTE_DRIVEN_CHECKS.issubset(check_names)


async def test_ensure_initialized_keeps_explicit_decorator_handler() -> None:
    app = FastAPI()
    config = SecurityConfig(enable_redis=False, fail_on_misconfiguration=False)
    explicit_decorator = SecurityDecorator(config)
    app_state_decorator = SecurityDecorator(config)

    @explicit_decorator.require_auth()
    @app.get("/needs-auth")
    async def needs_auth_endpoint() -> dict[str, str]:
        return {"message": "ok"}

    @app_state_decorator.rate_limit(requests=10, window=60)
    @app.get("/rate-limited")
    async def rate_limited_endpoint() -> dict[str, str]:
        return {"message": "ok"}

    app.state.guard_decorator = app_state_decorator
    middleware = SecurityMiddleware(app, config=config)
    middleware.set_decorator_handler(explicit_decorator)

    await middleware._ensure_initialized(_request_scoped_to(app))

    assert middleware.guard_decorator is explicit_decorator
    assert middleware.security_pipeline is not None
    check_names = set(middleware.security_pipeline.get_check_names())
    assert "authentication" in check_names


async def test_ensure_initialized_leaves_decorator_none_when_app_has_no_state() -> None:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=config)

    scope: dict[str, object] = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
        "state": {},
    }
    request_without_app = Request(scope)

    await middleware._ensure_initialized(request_without_app)

    assert middleware.guard_decorator is None
    assert middleware.security_pipeline is not None


async def test_ensure_initialized_ignores_non_mapping_request_scope() -> None:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=config)

    await middleware._ensure_initialized(Mock())

    assert middleware.guard_decorator is None
    assert middleware.security_pipeline is not None
