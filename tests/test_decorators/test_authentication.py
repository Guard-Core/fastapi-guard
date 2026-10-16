from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from guard import SecurityConfig, SecurityDecorator
from guard.middleware import SecurityMiddleware


@pytest.fixture
async def auth_decorator_app(security_config: SecurityConfig) -> FastAPI:
    """Create FastAPI app with authentication decorator integration."""
    app = FastAPI()

    security_config.trusted_proxies = ("127.0.0.1",)
    security_config.whitelist = (*security_config.whitelist, "8.8.8.8")
    security_config.enforce_https = False
    security_config.enable_penetration_detection = False
    security_config.auth_verifier = lambda request, credential: (
        {"user": "ok"} if credential else None
    )

    decorator = SecurityDecorator(security_config)

    @decorator.require_https()
    @app.get("/secure")
    async def secure_endpoint() -> dict[str, str]:
        return {"message": "HTTPS required"}

    @decorator.require_auth()
    @app.get("/auth-default")
    async def auth_default_endpoint() -> dict[str, str]:
        return {"message": "Auth required (default)"}

    @decorator.require_auth(type="basic")
    @app.get("/auth-basic")
    async def auth_basic_endpoint() -> dict[str, str]:
        return {"message": "Basic auth required"}

    @decorator.api_key_auth()
    @app.get("/api-key-default")
    async def api_key_default_endpoint() -> dict[str, str]:
        return {"message": "API key required (default header)"}

    @decorator.api_key_auth(header_name="Authorization")
    @app.post("/api-key-custom")
    async def api_key_custom_endpoint() -> dict[str, str]:
        return {"message": "API key required (custom header)"}

    @decorator.require_headers({"X-API-Version": "v1"})
    @app.get("/headers-single")
    async def headers_single_endpoint() -> dict[str, str]:
        return {"message": "Single header required"}

    @decorator.require_headers({"X-API-Version": "v2", "X-Client-ID": "required"})
    @app.post("/headers-multiple")
    async def headers_multiple_endpoint() -> dict[str, str]:
        return {"message": "Multiple headers required"}

    app.add_middleware(SecurityMiddleware, config=security_config)
    app.state.guard_decorator = decorator

    return app


@pytest.mark.parametrize(
    "route_path,expected_attr,expected_value,description",
    [
        ("/secure", "require_https", True, "require_https decorator"),
        ("/auth-default", "auth_required", "bearer", "require_auth default decorator"),
        ("/auth-basic", "auth_required", "basic", "require_auth custom type decorator"),
        (
            "/api-key-default",
            "api_key_required",
            True,
            "api_key_auth default decorator",
        ),
        (
            "/api-key-custom",
            "api_key_required",
            True,
            "api_key_auth custom header decorator",
        ),
    ],
)
async def test_authentication_decorators_applied(
    auth_decorator_app: FastAPI,
    route_path: str,
    expected_attr: str,
    expected_value: str | bool,
    description: str,
) -> None:
    """Test that authentication decorators are applied correctly."""
    for route in auth_decorator_app.routes:
        if isinstance(route, APIRoute) and route.path == route_path:
            assert hasattr(route.endpoint, "_guard_route_id"), (
                f"{description} should have route ID"
            )

            decorator = auth_decorator_app.state.guard_decorator
            route_id = route.endpoint._guard_route_id
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None, f"{description} should have route config"
            assert getattr(route_config, expected_attr) == expected_value, (
                f"{description} should have correct {expected_attr}"
            )


@pytest.mark.parametrize(
    "route_path,expected_headers,description",
    [
        ("/api-key-default", {"X-API-Key": "required"}, "api_key_auth default header"),
        (
            "/api-key-custom",
            {"Authorization": "required"},
            "api_key_auth custom header",
        ),
        ("/headers-single", {"X-API-Version": "v1"}, "require_headers single header"),
        (
            "/headers-multiple",
            {"X-API-Version": "v2", "X-Client-ID": "required"},
            "require_headers multiple headers",
        ),
    ],
)
async def test_header_requirements_applied(
    auth_decorator_app: FastAPI,
    route_path: str,
    expected_headers: dict[str, str],
    description: str,
) -> None:
    """Test that header requirement decorators are applied correctly."""
    for route in auth_decorator_app.routes:
        if isinstance(route, APIRoute) and route.path == route_path:
            assert hasattr(route.endpoint, "_guard_route_id"), (
                f"{description} should have route ID"
            )

            decorator = auth_decorator_app.state.guard_decorator
            route_id = route.endpoint._guard_route_id
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None, f"{description} should have route config"
            for header, value in expected_headers.items():
                assert route_config.required_headers[header] == value, (
                    f"{description} should require {header}={value}"
                )


@pytest.mark.parametrize(
    "endpoint,missing_header,expected_message,description",
    [
        (
            "/api-key-default",
            "X-API-Key",
            "Missing required header: X-API-Key",
            "API key default header missing",
        ),
        (
            "/api-key-custom",
            "Authorization",
            "Missing required header: Authorization",
            "API key custom header missing",
        ),
        (
            "/headers-multiple",
            "X-Client-ID",
            "Missing required header: X-Client-ID",
            "Multiple headers partially missing",
        ),
    ],
)
async def test_missing_headers_blocked(
    auth_decorator_app: FastAPI,
    endpoint: str,
    missing_header: str,
    expected_message: str,
    description: str,
) -> None:
    """Test that missing required headers are blocked."""
    async with AsyncClient(
        transport=ASGITransport(app=auth_decorator_app), base_url="http://test"
    ) as client:
        headers = {"X-Forwarded-For": "203.0.113.5"}
        if endpoint == "/headers-multiple":
            headers["X-API-Version"] = "v2"

        method = (
            "post"
            if endpoint == "/api-key-custom" or endpoint == "/headers-multiple"
            else "get"
        )
        response = await getattr(client, method)(endpoint, headers=headers)

        assert response.status_code == 400, f"{description} should return 400"
        assert expected_message in response.text, (
            f"{description} should show correct error message"
        )


@pytest.mark.parametrize(
    "endpoint,headers,expected_message,description",
    [
        (
            "/api-key-default",
            {"X-Forwarded-For": "203.0.113.5", "X-API-Key": "test-key"},
            "API key required (default header)",
            "API key with header allowed",
        ),
        (
            "/headers-multiple",
            {
                "X-Forwarded-For": "203.0.113.5",
                "X-API-Version": "v2",
                "X-Client-ID": "test-client",
            },
            "Multiple headers required",
            "All required headers present",
        ),
    ],
)
async def test_valid_headers_allowed(
    auth_decorator_app: FastAPI,
    endpoint: str,
    headers: dict[str, str],
    expected_message: str,
    description: str,
) -> None:
    """Test that requests with valid headers are allowed."""
    async with AsyncClient(
        transport=ASGITransport(app=auth_decorator_app), base_url="http://test"
    ) as client:
        method = "post" if endpoint == "/headers-multiple" else "get"
        response = await getattr(client, method)(endpoint, headers=headers)

        assert response.status_code == 200, f"{description} should return 200"
        assert response.json()["message"] == expected_message, (
            f"{description} should return correct message"
        )


async def test_authentication_endpoints_response(auth_decorator_app: FastAPI) -> None:
    """Test calling authentication endpoints and their responses."""
    async with AsyncClient(
        transport=ASGITransport(app=auth_decorator_app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/secure",
            headers={"X-Forwarded-For": "203.0.113.5"},
            follow_redirects=False,
        )
        assert response.status_code == 301

        async with AsyncClient(
            transport=ASGITransport(app=auth_decorator_app), base_url="https://test"
        ) as https_client:
            response = await https_client.get(
                "/secure", headers={"X-Forwarded-For": "203.0.113.5"}
            )
            assert response.status_code == 200
            assert response.json()["message"] == "HTTPS required"

        response = await client.get(
            "/auth-default",
            headers={
                "X-Forwarded-For": "203.0.113.5",
                "Authorization": "Bearer test-token",
            },
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Auth required (default)"

        response = await client.get(
            "/auth-basic",
            headers={
                "X-Forwarded-For": "203.0.113.5",
                "Authorization": "Basic dGVzdDp0ZXN0",
            },
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Basic auth required"

        response = await client.get(
            "/headers-single",
            headers={"X-Forwarded-For": "203.0.113.5", "X-API-Version": "v1"},
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Single header required"

        response = await client.post(
            "/api-key-custom",
            headers={"X-Forwarded-For": "203.0.113.5", "Authorization": "test-key"},
        )
        assert response.status_code == 200
        assert response.json()["message"] == "API key required (custom header)"


async def test_authentication_decorators_unit(security_config: SecurityConfig) -> None:
    """Unit tests for authentication decorators."""
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    https_decorator = decorator.require_https()
    decorated_func = https_decorator(mock_func)

    route_id = decorated_func._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert route_config.require_https is True

    auth_decorator = decorator.require_auth()
    decorated_func2 = auth_decorator(mock_func)

    route_id2 = decorated_func2._guard_route_id
    route_config2 = decorator.get_route_config(route_id2)
    assert route_config2 is not None
    assert route_config2.auth_required == "bearer"

    auth_custom_decorator = decorator.require_auth(type="digest")
    decorated_func3 = auth_custom_decorator(mock_func)

    route_id3 = decorated_func3._guard_route_id
    route_config3 = decorator.get_route_config(route_id3)
    assert route_config3 is not None
    assert route_config3.auth_required == "digest"

    api_key_decorator = decorator.api_key_auth()
    decorated_func4 = api_key_decorator(mock_func)

    route_id4 = decorated_func4._guard_route_id
    route_config4 = decorator.get_route_config(route_id4)
    assert route_config4 is not None
    assert route_config4.api_key_required is True
    assert route_config4.required_headers["X-API-Key"] == "required"

    api_key_custom_decorator = decorator.api_key_auth(header_name="X-Custom-Key")
    decorated_func5 = api_key_custom_decorator(mock_func)

    route_id5 = decorated_func5._guard_route_id
    route_config5 = decorator.get_route_config(route_id5)
    assert route_config5 is not None
    assert route_config5.api_key_required is True
    assert route_config5.required_headers["X-Custom-Key"] == "required"

    headers_decorator = decorator.require_headers(
        {"X-Test": "value", "X-Other": "required"}
    )
    decorated_func6 = headers_decorator(mock_func)

    route_id6 = decorated_func6._guard_route_id
    route_config6 = decorator.get_route_config(route_id6)
    assert route_config6 is not None
    assert route_config6.required_headers["X-Test"] == "value"
    assert route_config6.required_headers["X-Other"] == "required"


async def test_authentication_failures_blocked(auth_decorator_app: FastAPI) -> None:
    """Test that authentication failures are properly blocked and logged."""
    async with AsyncClient(
        transport=ASGITransport(app=auth_decorator_app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/auth-default", headers={"X-Forwarded-For": "8.8.8.8"}
        )
        assert response.status_code == 401
        assert "Authentication required" in response.text

        response = await client.get(
            "/auth-default",
            headers={
                "X-Forwarded-For": "8.8.8.8",
                "Authorization": "Invalid token-format",
            },
        )
        assert response.status_code == 401
        assert "Authentication required" in response.text

        response = await client.get(
            "/auth-basic", headers={"X-Forwarded-For": "8.8.8.8"}
        )
        assert response.status_code == 401
        assert "Authentication required" in response.text

        response = await client.get(
            "/auth-basic",
            headers={
                "X-Forwarded-For": "8.8.8.8",
                "Authorization": "Bearer wrong-type",
            },
        )
        assert response.status_code == 401
        assert "Authentication required" in response.text


async def test_auth_passive_mode(security_config: SecurityConfig) -> None:
    """Test authentication check in passive mode."""
    app = FastAPI()
    security_config.passive_mode = True
    security_config.trusted_proxies = ("127.0.0.1",)

    decorator = SecurityDecorator(security_config)

    @decorator.require_auth("bearer")
    @app.get("/auth-test")
    async def auth_endpoint() -> dict[str, str]:
        return {"message": "ok"}

    app.add_middleware(SecurityMiddleware, config=security_config)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/auth-test", headers={"X-Forwarded-For": "8.8.8.8"}
        )
        assert response.status_code == 200
