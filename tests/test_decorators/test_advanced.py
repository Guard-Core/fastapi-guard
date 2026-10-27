from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from guard_core.decorators import get_route_id
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from guard import SecurityConfig, SecurityDecorator
from guard.middleware import SecurityMiddleware


@pytest.fixture
async def advanced_decorator_app(security_config: SecurityConfig) -> FastAPI:
    """Create FastAPI app with advanced decorator integration."""
    app = FastAPI()

    security_config.trusted_proxies = ("127.0.0.1",)
    security_config.enable_penetration_detection = False
    security_config.whitelist = ()

    decorator = SecurityDecorator(security_config)

    @decorator.time_window("09:00", "17:00", "UTC")
    @app.get("/business-hours")
    async def business_hours_endpoint() -> dict[str, str]:
        return {"message": "Business hours access"}

    @decorator.time_window("22:00", "06:00", "UTC")  # Night hours
    @app.get("/night-hours")
    async def night_hours_endpoint() -> dict[str, str]:
        return {"message": "Night hours access"}

    @decorator.suspicious_detection(enabled=True)
    @app.get("/suspicious-enabled")
    async def suspicious_enabled_endpoint() -> dict[str, str]:
        return {"message": "Suspicious detection enabled"}

    @decorator.suspicious_detection(enabled=False)
    @app.get("/suspicious-disabled")
    async def suspicious_disabled_endpoint() -> dict[str, str]:
        return {"message": "Suspicious detection disabled"}

    @decorator.honeypot_detection(["bot_trap", "hidden_field"])
    @app.post("/form-honeypot")
    async def form_honeypot_endpoint() -> dict[str, str]:
        return {"message": "Form submitted successfully"}

    @decorator.honeypot_detection(["spam_check", "robot_field"])
    @app.post("/json-honeypot")
    async def json_honeypot_endpoint() -> dict[str, str]:
        return {"message": "JSON submitted successfully"}

    app.add_middleware(SecurityMiddleware, config=security_config)
    app.state.guard_decorator = decorator

    return app


@pytest.mark.parametrize(
    "endpoint,mock_hour,expected_status,description",
    [
        ("/business-hours", 12, 200, "Noon should be allowed during business hours"),
        ("/business-hours", 6, 403, "Early morning should be blocked"),
        ("/business-hours", 20, 403, "Evening should be blocked"),
        ("/night-hours", 23, 200, "Late night should be allowed"),
        ("/night-hours", 2, 200, "Early morning should be allowed"),
        ("/night-hours", 14, 403, "Afternoon should be blocked"),
    ],
)
async def test_time_window_restrictions(
    advanced_decorator_app: FastAPI,
    endpoint: str,
    mock_hour: int,
    expected_status: int,
    description: str,
) -> None:
    """Test time window restrictions."""
    from datetime import datetime, timezone

    # Mock datetime.now to return a specific hour
    mock_datetime = datetime(2024, 1, 1, mock_hour, 0, 0, tzinfo=timezone.utc)

    # Patch datetime at both locations where it's used
    with patch(
        "guard_core.core.checks.implementations.time_window.datetime"
    ) as mock_dt:
        mock_dt.now.return_value = mock_datetime
        mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)

        async with AsyncClient(
            transport=ASGITransport(app=advanced_decorator_app), base_url="http://test"
        ) as client:
            response = await client.get(
                endpoint,
                headers={"X-Forwarded-For": "203.0.113.5"},
            )
            assert response.status_code == expected_status, description


async def test_suspicious_detection_enabled(advanced_decorator_app: FastAPI) -> None:
    """Test that suspicious detection decorator is applied correctly."""
    # Find the route and verify decorator was applied
    for route in advanced_decorator_app.routes:
        if isinstance(route, APIRoute) and route.path == "/suspicious-enabled":
            assert hasattr(route.endpoint, "_guard_route_id")

            decorator = advanced_decorator_app.state.guard_decorator
            route_id = get_route_id(route.endpoint)
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None
            assert route_config.enable_suspicious_detection is True


async def test_suspicious_detection_disabled(advanced_decorator_app: FastAPI) -> None:
    """Test that suspicious detection disabled decorator is applied correctly."""
    # Find the route and verify decorator was applied
    for route in advanced_decorator_app.routes:
        if isinstance(route, APIRoute) and route.path == "/suspicious-disabled":
            assert hasattr(route.endpoint, "_guard_route_id")

            decorator = advanced_decorator_app.state.guard_decorator
            route_id = get_route_id(route.endpoint)
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None
            assert route_config.enable_suspicious_detection is False


async def test_suspicious_endpoints_response(advanced_decorator_app: FastAPI) -> None:
    """Test calling suspicious endpoints and their responses from a
    non-whitelisted client, so SuspiciousActivityCheck genuinely runs
    instead of being short-circuited by is_whitelisted."""
    async with AsyncClient(
        transport=ASGITransport(app=advanced_decorator_app), base_url="http://test"
    ) as client:
        # Test suspicious enabled endpoint
        response = await client.get(
            "/suspicious-enabled", headers={"X-Forwarded-For": "8.8.8.8"}
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Suspicious detection enabled"

        # Test suspicious disabled endpoint
        response = await client.get(
            "/suspicious-disabled", headers={"X-Forwarded-For": "8.8.8.8"}
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Suspicious detection disabled"


async def test_suspicious_detection_enabled_blocks_malicious_request(
    advanced_decorator_app: FastAPI,
) -> None:
    """A malicious request to a route with suspicious detection enabled is
    blocked, proving the decorator actually scans the request."""
    async with AsyncClient(
        transport=ASGITransport(app=advanced_decorator_app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/suspicious-enabled",
            params={"q": "UNION SELECT NULL--"},
            headers={"X-Forwarded-For": "8.8.8.8"},
        )
        assert response.status_code == 400
        assert "Suspicious activity detected" in response.text


async def test_suspicious_detection_disabled_allows_malicious_request(
    advanced_decorator_app: FastAPI,
) -> None:
    """The same malicious request passes on a route where suspicious
    detection is explicitly disabled by the decorator."""
    async with AsyncClient(
        transport=ASGITransport(app=advanced_decorator_app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/suspicious-disabled",
            params={"q": "UNION SELECT NULL--"},
            headers={"X-Forwarded-For": "8.8.8.8"},
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Suspicious detection disabled"


@pytest.mark.parametrize(
    "endpoint,expected_fields,description",
    [
        (
            "/form-honeypot",
            ["bot_trap", "hidden_field"],
            "Form honeypot should have trap fields configured",
        ),
        (
            "/json-honeypot",
            ["spam_check", "robot_field"],
            "JSON honeypot should have trap fields configured",
        ),
    ],
)
async def test_honeypot_detection_configuration(
    advanced_decorator_app: FastAPI,
    endpoint: str,
    expected_fields: list[str],
    description: str,
) -> None:
    """Test that honeypot detection decorators are configured correctly."""
    # Find the route and verify decorator was applied
    for route in advanced_decorator_app.routes:
        if isinstance(route, APIRoute) and route.path == endpoint:
            assert hasattr(route.endpoint, "_guard_route_id")

            decorator = advanced_decorator_app.state.guard_decorator
            route_id = get_route_id(route.endpoint)
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None
            assert len(route_config.custom_validators) == 1, (
                "Should have one custom validator"
            )

    trap = expected_fields[0]
    form = endpoint == "/form-honeypot"
    headers = {"X-Forwarded-For": "203.0.113.5"}

    async def post(value: str) -> int:
        async with AsyncClient(
            transport=ASGITransport(app=advanced_decorator_app),
            base_url="http://test",
        ) as client:
            if form:
                response = await client.post(
                    endpoint, headers=headers, data={trap: value}
                )
            else:
                response = await client.post(
                    endpoint, headers=headers, json={trap: value}
                )
        return response.status_code

    assert await post("") == 200, "An empty trap field should pass"
    assert await post("bot") == 403, "A filled trap field should be rejected"


async def test_honeypot_detection_basic_functionality(
    advanced_decorator_app: FastAPI,
) -> None:
    """Test basic honeypot detection functionality - clean requests should pass."""
    async with AsyncClient(
        transport=ASGITransport(app=advanced_decorator_app), base_url="http://test"
    ) as client:
        # Test clean form data passes
        response = await client.post(
            "/form-honeypot",
            data={"name": "John", "email": "john@example.com"},
            headers={
                "X-Forwarded-For": "203.0.113.5",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert response.status_code == 200

        # Test clean JSON data passes
        response = await client.post(
            "/json-honeypot",
            json={"name": "Jane", "message": "Hello"},
            headers={"X-Forwarded-For": "203.0.113.5"},
        )
        assert response.status_code == 200


async def test_honeypot_form_detection(security_config: SecurityConfig) -> None:
    decorator = SecurityDecorator(security_config)
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["bot_trap"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    mock_request = AsyncMock()
    mock_request.method = "POST"
    mock_request.url_full = "http://test/"
    mock_request.state = SimpleNamespace()
    form_body = b"bot_trap=filled"
    mock_request.headers.get = lambda key, default="": {
        "content-type": "application/x-www-form-urlencoded",
        "content-length": str(len(form_body)),
    }.get(key, default)
    mock_request.body.return_value = form_body
    mock_request.read_body_prefix_until_idle.return_value = form_body

    result = await validator(mock_request)
    assert result.status_code == 403


async def test_honeypot_json_exception(security_config: SecurityConfig) -> None:
    decorator = SecurityDecorator(security_config)
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["spam_check"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    mock_request = AsyncMock()
    mock_request.method = "POST"
    mock_request.url_full = "http://test/"
    mock_request.headers.get = lambda key, default="": (
        "application/json" if key == "content-type" else default
    )
    mock_request.body.side_effect = Exception("JSON error")

    result = await validator(mock_request)
    assert result is None


async def test_honeypot_json_detection(security_config: SecurityConfig) -> None:
    decorator = SecurityDecorator(security_config)
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["spam_check"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    mock_request = AsyncMock()
    mock_request.method = "POST"
    mock_request.url_full = "http://test/"
    mock_request.state = SimpleNamespace()
    json_body = b'{"spam_check": "filled"}'
    mock_request.headers.get = lambda key, default="": {
        "content-type": "application/json",
        "content-length": str(len(json_body)),
    }.get(key, default)
    mock_request.body.return_value = json_body
    mock_request.read_body_prefix_until_idle.return_value = json_body

    result = await validator(mock_request)
    assert result.status_code == 403
