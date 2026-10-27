from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from guard_core.decorators import get_route_id
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from guard import SecurityConfig, SecurityDecorator
from guard.middleware import SecurityMiddleware


@pytest.fixture
async def rate_limiting_decorator_app(security_config: SecurityConfig) -> FastAPI:
    """Create FastAPI app with rate limiting decorator integration."""
    app = FastAPI()

    security_config.trusted_proxies = ("127.0.0.1",)
    security_config.enable_penetration_detection = False

    decorator = SecurityDecorator(security_config)

    @decorator.rate_limit(requests=10, window=60)
    @app.get("/rate-limited")
    async def rate_limited_endpoint() -> dict[str, str]:
        return {"message": "Rate limited endpoint"}

    @decorator.geo_rate_limit({"US": (100, 3600), "CN": (10, 3600), "*": (50, 3600)})
    @app.get("/geo-rate-limited")
    async def geo_rate_limited_endpoint() -> dict[str, str]:
        return {"message": "Geo rate limited endpoint"}

    app.add_middleware(SecurityMiddleware, config=security_config)
    app.state.guard_decorator = decorator

    return app


@pytest.fixture
async def open_rate_limiting_decorator_app(security_config: SecurityConfig) -> FastAPI:
    """Same routes as rate_limiting_decorator_app but with no global IP
    whitelist, so a non-whitelisted client actually reaches the
    rate_limit/geo_rate_limit decorators instead of being bypassed."""
    app = FastAPI()

    security_config.trusted_proxies = ("127.0.0.1",)
    security_config.enable_penetration_detection = False
    security_config.whitelist = ()

    decorator = SecurityDecorator(security_config)

    @decorator.rate_limit(requests=10, window=60)
    @app.get("/rate-limited")
    async def rate_limited_endpoint() -> dict[str, str]:
        return {"message": "Rate limited endpoint"}

    @decorator.geo_rate_limit({"US": (100, 3600), "CN": (10, 3600), "*": (50, 3600)})
    @app.get("/geo-rate-limited")
    async def geo_rate_limited_endpoint() -> dict[str, str]:
        return {"message": "Geo rate limited endpoint"}

    app.add_middleware(SecurityMiddleware, config=security_config)
    app.state.guard_decorator = decorator

    return app


@pytest.fixture
async def open_rate_limited_app(security_config: SecurityConfig) -> FastAPI:
    """Rate-limited route with no global IP whitelist, so non-whitelisted
    clients pass the IP gate and actually reach the rate_limit decorator."""
    app = FastAPI()

    security_config.trusted_proxies = ("127.0.0.1",)
    security_config.enable_penetration_detection = False
    security_config.whitelist = ()

    decorator = SecurityDecorator(security_config)

    @decorator.rate_limit(requests=2, window=60)
    @app.get("/rate-limited-open")
    async def rate_limited_open_endpoint() -> dict[str, str]:
        return {"message": "Rate limited endpoint"}

    app.add_middleware(SecurityMiddleware, config=security_config)
    app.state.guard_decorator = decorator

    return app


@pytest.fixture
async def route_whitelisted_rate_limited_app(
    security_config: SecurityConfig,
) -> FastAPI:
    """Route grants IP access via require_ip while rate_limit still applies,
    proving the route whitelist is not a rate-limit exemption (D1)."""
    app = FastAPI()

    security_config.trusted_proxies = ("127.0.0.1",)
    security_config.enable_penetration_detection = False
    security_config.whitelist = ()

    decorator = SecurityDecorator(security_config)

    @decorator.require_ip(whitelist=["8.8.8.8"])
    @decorator.rate_limit(requests=2, window=60)
    @app.get("/route-whitelisted-rate-limited")
    async def route_whitelisted_endpoint() -> dict[str, str]:
        return {"message": "Route whitelisted endpoint"}

    app.add_middleware(SecurityMiddleware, config=security_config)
    app.state.guard_decorator = decorator

    return app


@pytest.mark.parametrize(
    "route_path,expected_rate_limit,expected_window,description",
    [
        ("/rate-limited", 10, 60, "rate_limit decorator"),
    ],
)
async def test_rate_limiting_decorators_applied(
    rate_limiting_decorator_app: FastAPI,
    route_path: str,
    expected_rate_limit: int,
    expected_window: int,
    description: str,
) -> None:
    """Test that rate limiting decorators are applied correctly."""
    for route in rate_limiting_decorator_app.routes:
        if isinstance(route, APIRoute) and route.path == route_path:
            assert hasattr(route.endpoint, "_guard_route_id"), (
                f"{description} should have route ID"
            )

            decorator = rate_limiting_decorator_app.state.guard_decorator
            route_id = get_route_id(route.endpoint)
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None, f"{description} should have route config"
            assert route_config.rate_limit == expected_rate_limit, (
                f"{description} should have correct rate limit"
            )
            assert route_config.rate_limit_window == expected_window, (
                f"{description} should have correct rate limit window"
            )


async def test_geo_rate_limit_decorator_applied(
    rate_limiting_decorator_app: FastAPI,
) -> None:
    """Test that geo rate limit decorator is applied correctly."""
    for route in rate_limiting_decorator_app.routes:
        if isinstance(route, APIRoute) and route.path == "/geo-rate-limited":
            assert hasattr(route.endpoint, "_guard_route_id"), (
                "geo_rate_limit decorator should have route ID"
            )

            decorator = rate_limiting_decorator_app.state.guard_decorator
            route_id = get_route_id(route.endpoint)
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None, "geo_rate_limit should have route config"
            expected_limits = {"US": (100, 3600), "CN": (10, 3600), "*": (50, 3600)}
            assert route_config.geo_rate_limits == expected_limits, (
                "geo_rate_limit should store limits in geo_rate_limits"
            )


@pytest.mark.parametrize(
    "endpoint,expected_message,description",
    [
        ("/rate-limited", "Rate limited endpoint", "rate_limit endpoint"),
        ("/geo-rate-limited", "Geo rate limited endpoint", "geo_rate_limit endpoint"),
    ],
)
async def test_rate_limiting_endpoints_response(
    open_rate_limiting_decorator_app: FastAPI,
    endpoint: str,
    expected_message: str,
    description: str,
) -> None:
    """Test calling rate limiting endpoints and their responses from a
    non-whitelisted client, so the request genuinely traverses the
    rate_limit/geo_rate_limit decorators instead of being short-circuited
    by is_whitelisted."""
    async with AsyncClient(
        transport=ASGITransport(app=open_rate_limiting_decorator_app),
        base_url="http://test",
    ) as client:
        headers = {"X-Forwarded-For": "8.8.8.8"}

        response = await client.get(endpoint, headers=headers)

        assert response.status_code == 200, f"{description} should return 200"
        assert expected_message in response.text, (
            f"{description} should contain '{expected_message}'"
        )


async def test_rate_limited_route_blocks_non_whitelisted_client_at_ip_gate(
    rate_limiting_decorator_app: FastAPI,
) -> None:
    """A decorated route with no route ip_whitelist, but a GLOBAL whitelist
    configured, returns 403 for a non-whitelisted client at the IP gate --
    the rate_limit decorator never runs."""
    async with AsyncClient(
        transport=ASGITransport(app=rate_limiting_decorator_app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/rate-limited", headers={"X-Forwarded-For": "8.8.8.8"}
        )

        assert response.status_code == 403


async def test_rate_limit_enforced_for_non_whitelisted_client(
    open_rate_limited_app: FastAPI,
) -> None:
    """Without a global whitelist, a non-whitelisted client passes the IP
    gate and is genuinely rate-limited by the decorator."""
    async with AsyncClient(
        transport=ASGITransport(app=open_rate_limited_app), base_url="http://test"
    ) as client:
        headers = {"X-Forwarded-For": "8.8.8.8"}

        for _ in range(2):
            response = await client.get("/rate-limited-open", headers=headers)
            assert response.status_code == 200

        response = await client.get("/rate-limited-open", headers=headers)
        assert response.status_code == 429


async def test_route_whitelisted_client_still_rate_limited(
    route_whitelisted_rate_limited_app: FastAPI,
) -> None:
    """A route-whitelisted IP is granted IP access but is not exempt from
    the route's rate_limit decorator (D1)."""
    async with AsyncClient(
        transport=ASGITransport(app=route_whitelisted_rate_limited_app),
        base_url="http://test",
    ) as client:
        headers = {"X-Forwarded-For": "8.8.8.8"}

        for _ in range(2):
            response = await client.get(
                "/route-whitelisted-rate-limited", headers=headers
            )
            assert response.status_code == 200

        response = await client.get("/route-whitelisted-rate-limited", headers=headers)
        assert response.status_code == 429


async def test_rate_limiting_decorators_unit(security_config: SecurityConfig) -> None:
    """Unit tests for rate limiting decorators."""
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    # Test rate_limit decorator
    rate_limit_decorator = decorator.rate_limit(requests=5, window=120)
    decorated_func = rate_limit_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert route_config.rate_limit == 5
    assert route_config.rate_limit_window == 120

    # Test geo_rate_limit decorator
    mock_func2 = Mock()
    mock_func2.__name__ = mock_func2.__qualname__ = "test_func2"
    mock_func2.__module__ = "test_module"

    limits = {"US": (100, 3600), "EU": (50, 3600)}
    geo_rate_limit_decorator = decorator.geo_rate_limit(limits)
    decorated_func2 = geo_rate_limit_decorator(mock_func2)

    route_id2 = get_route_id(decorated_func2)
    route_config2 = decorator.get_route_config(route_id2)
    assert route_config2 is not None
    assert route_config2.geo_rate_limits == limits
