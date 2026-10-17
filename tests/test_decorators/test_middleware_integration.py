from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import FastAPI, Request, Response
from guard_core.decorators.base import RouteConfig
from guard_core.detection_result import DetectionResult
from guard_core.handlers.behavior_handler import BehaviorRule
from guard_core.protocols import GuardResponse
from starlette.datastructures import Headers

from guard import SecurityConfig, SecurityDecorator
from guard.adapters import StarletteGuardResponse
from guard.middleware import SecurityMiddleware


def _http_scope(
    *, path: str = "/test", headers: list[tuple[bytes, bytes]] | None = None
) -> dict:
    return {
        "type": "http",
        "method": "GET",
        "path": path,
        "root_path": "",
        "query_string": b"",
        "headers": headers or [],
        "client": ("127.0.0.1", 5555),
        "scheme": "http",
        "server": ("testserver", 80),
        "state": {},
    }


async def test_set_decorator_handler() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    decorator = SecurityDecorator(config)
    middleware.set_decorator_handler(decorator)

    assert middleware.guard_decorator is decorator

    middleware.set_decorator_handler(None)
    assert middleware.guard_decorator is None


async def test_get_endpoint_id_with_route() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
        "state": {},
    }
    mock_request = Request(scope)
    mock_request.state.guard_endpoint_id = "test_module.test_function"

    endpoint_id = middleware._get_endpoint_id(mock_request)
    assert endpoint_id == "test_module.test_function"

    scope2 = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
        "state": {},
    }
    mock_request2 = Request(scope2)
    endpoint_id = middleware._get_endpoint_id(mock_request2)
    assert endpoint_id == "GET:/test"


async def test_should_bypass_check() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    assert not middleware.route_resolver.should_bypass_check("ip", None)

    mock_route_config = Mock()
    mock_route_config.bypassed_checks = {"ip"}
    assert middleware.route_resolver.should_bypass_check("ip", mock_route_config)
    assert not middleware.route_resolver.should_bypass_check(
        "rate_limit", mock_route_config
    )

    mock_route_config.bypassed_checks = {"all"}
    assert middleware.route_resolver.should_bypass_check("ip", mock_route_config)
    assert middleware.route_resolver.should_bypass_check(
        "rate_limit", mock_route_config
    )


async def test_check_route_ip_access_invalid_ip() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = None
    mock_route_config.ip_whitelist = None
    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = None

    result = await middleware._check_route_ip_access("invalid_ip", mock_route_config)
    assert result is False


async def test_check_route_ip_access_blacklist() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = ["192.168.1.100", "10.0.0.0/8"]
    mock_route_config.ip_whitelist = None
    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = None

    result = await middleware._check_route_ip_access("192.168.1.100", mock_route_config)
    assert result is False

    result = await middleware._check_route_ip_access("10.0.0.1", mock_route_config)
    assert result is False

    result = await middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is None


async def test_check_route_ip_access_whitelist() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = None
    mock_route_config.ip_whitelist = ["192.168.1.100", "10.0.0.0/8"]
    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = None

    result = await middleware._check_route_ip_access("192.168.1.100", mock_route_config)
    assert result is True

    result = await middleware._check_route_ip_access("10.0.0.1", mock_route_config)
    assert result is True

    result = await middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False


async def test_check_route_ip_access_countries() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_geo_handler = Mock()
    middleware.geo_ip_handler = mock_geo_handler

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = None
    mock_route_config.ip_whitelist = None

    mock_route_config.blocked_countries = ["XX"]
    mock_route_config.whitelist_countries = None
    mock_geo_handler.get_country.return_value = "XX"

    result = await middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False

    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = ["US"]
    mock_geo_handler.get_country.return_value = "US"

    result = await middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is True

    mock_geo_handler.get_country.return_value = "XX"
    result = await middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False

    mock_geo_handler.get_country.return_value = None
    result = await middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False


async def test_check_user_agent_allowed() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_route_config = Mock()
    mock_route_config.blocked_user_agents = [r"badbot"]

    with patch("guard_core.utils.is_user_agent_allowed", return_value=True):
        result = await middleware._check_user_agent_allowed("badbot", mock_route_config)
        assert result is False

        result = await middleware._check_user_agent_allowed(
            "goodbot", mock_route_config
        )
        assert result is True

    with patch(
        "guard_core.utils.is_user_agent_allowed", return_value=False
    ) as mock_global:
        result = await middleware._check_user_agent_allowed("somebot", None)
        assert result is False
        mock_global.assert_called_once()


async def test_time_window_error_handling() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    invalid_time_restrictions = {"invalid": "data"}

    with patch.object(middleware.logger, "error") as mock_error:
        result = await middleware._check_time_window(invalid_time_restrictions)
        assert result is True
        mock_error.assert_called_once()


async def test_time_window_overnight() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    time_restrictions = {"start": "22:00", "end": "06:00"}

    with patch("guard_core.core.validation.validator.datetime") as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "23:00"
        result = await middleware._check_time_window(time_restrictions)
        assert result is True

    with patch("guard_core.core.validation.validator.datetime") as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "05:00"
        result = await middleware._check_time_window(time_restrictions)
        assert result is True

    with patch("guard_core.core.validation.validator.datetime") as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "12:00"
        result = await middleware._check_time_window(time_restrictions)
        assert result is False


async def test_time_window_normal() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    time_restrictions = {"start": "09:00", "end": "17:00"}

    with patch("guard_core.core.validation.validator.datetime") as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "12:00"
        result = await middleware._check_time_window(time_restrictions)
        assert result is True

    with patch("guard_core.core.validation.validator.datetime") as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "20:00"
        result = await middleware._check_time_window(time_restrictions)
        assert result is False


async def test_behavioral_rules_without_guard_decorator() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    middleware.guard_decorator = None

    mock_request = Mock()
    mock_request.state.guard_decorator = None
    mock_route_config = Mock()
    mock_route_config.behavior_rules = [BehaviorRule("usage", threshold=5, window=3600)]

    await middleware._process_decorator_usage_rules(
        mock_request, "127.0.0.1", mock_route_config
    )
    await middleware._process_decorator_return_rules(
        mock_request, Mock(), "127.0.0.1", mock_route_config
    )


async def test_behavioral_usage_rules_with_decorator() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_guard_decorator = Mock()
    mock_behavior_tracker = Mock()
    mock_guard_decorator.behavior_tracker = mock_behavior_tracker
    middleware.guard_decorator = mock_guard_decorator

    mock_request = Mock()
    mock_request.scope = {
        "route": Mock(endpoint=Mock(__module__="test", __qualname__="test_func"))
    }
    mock_request.method = "GET"
    mock_request.url.path = "/test"
    mock_request.state.guard_decorator = mock_guard_decorator

    mock_route_config = Mock()
    usage_rule = BehaviorRule("usage", threshold=5, window=3600)
    mock_route_config.behavior_rules = [usage_rule]

    mock_behavior_tracker.track_endpoint_usage = AsyncMock(return_value=False)

    await middleware._process_decorator_usage_rules(
        mock_request, "127.0.0.1", mock_route_config
    )
    mock_behavior_tracker.apply_action.assert_not_called()

    mock_behavior_tracker.track_endpoint_usage = AsyncMock(return_value=True)
    mock_behavior_tracker.apply_action = AsyncMock()

    await middleware._process_decorator_usage_rules(
        mock_request, "127.0.0.1", mock_route_config
    )


async def test_behavioral_return_rules_with_decorator() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_guard_decorator = Mock()
    mock_behavior_tracker = Mock()
    mock_guard_decorator.behavior_tracker = mock_behavior_tracker
    middleware.guard_decorator = mock_guard_decorator

    mock_request = Mock()
    mock_request.scope = {
        "route": Mock(endpoint=Mock(__module__="test", __qualname__="test_func"))
    }
    mock_request.method = "GET"
    mock_request.url.path = "/test"
    mock_request.state.guard_decorator = mock_guard_decorator

    mock_response = Mock()
    mock_route_config = Mock()
    return_rule = BehaviorRule(
        "return_pattern", threshold=3, window=3600, pattern="win"
    )
    mock_route_config.behavior_rules = [return_rule]

    mock_behavior_tracker.track_return_pattern = AsyncMock(return_value=False)

    await middleware._process_decorator_return_rules(
        mock_request, mock_response, "127.0.0.1", mock_route_config
    )
    mock_behavior_tracker.apply_action.assert_not_called()

    mock_behavior_tracker.track_return_pattern = AsyncMock(return_value=True)
    mock_behavior_tracker.apply_action = AsyncMock()

    await middleware._process_decorator_return_rules(
        mock_request, mock_response, "127.0.0.1", mock_route_config
    )


async def test_get_route_decorator_config_no_route_id() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_request = Mock()
    mock_request.state = Mock(spec=[])

    result = middleware.route_resolver.get_route_config(mock_request)
    assert result is None


async def test_get_route_decorator_config_no_guard_decorator() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_request = Mock()
    mock_request.state = Mock()
    mock_request.state.guard_route_id = "some_route"
    mock_request.state.guard_decorator = None

    result = middleware.route_resolver.get_route_config(mock_request)
    assert result is None


async def test_get_route_decorator_config_fallback_to_middleware_decorator() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    decorator = SecurityDecorator(config)
    middleware.set_decorator_handler(decorator)

    mock_request = Mock()
    mock_request.state = Mock()
    mock_request.state.guard_route_id = "nonexistent_route"
    mock_request.state.guard_decorator = None

    result = middleware.route_resolver.get_route_config(mock_request)
    assert result is None


async def test_get_route_decorator_config_no_matching_route() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    decorator = SecurityDecorator(config)

    mock_request = Mock()
    mock_request.url.path = "/nonexistent"
    mock_request = Mock()
    mock_request.state = Mock()
    mock_request.state.guard_route_id = "nonexistent_route"
    mock_request.state.guard_decorator = decorator

    result = middleware.route_resolver.get_route_config(mock_request)
    assert result is None


async def test_bypass_all_security_checks() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_route_config = RouteConfig()
    mock_route_config.bypassed_checks = {"all"}

    mock_request = Request(_http_scope())

    async def mock_call_next(request: Request) -> Response:
        return Response("bypassed", status_code=200)

    with patch.object(
        middleware.route_resolver, "get_route_config", return_value=mock_route_config
    ):
        response = await middleware.dispatch(mock_request, mock_call_next)
        assert response.status_code == 200


async def test_bypass_all_security_checks_with_custom_modifier() -> None:
    app = FastAPI()

    async def custom_modifier(response: GuardResponse) -> GuardResponse:
        del response
        return StarletteGuardResponse(Response("custom modified", status_code=202))

    config = SecurityConfig(custom_response_modifier=custom_modifier)
    middleware = SecurityMiddleware(app, config=config)

    mock_route_config = RouteConfig()
    mock_route_config.bypassed_checks = {"all"}

    mock_request = Request(_http_scope())

    async def mock_call_next(request: Request) -> Response:
        return Response("bypassed", status_code=200)

    with patch.object(
        middleware.route_resolver, "get_route_config", return_value=mock_route_config
    ):
        response = await middleware.dispatch(mock_request, mock_call_next)
        assert response.status_code == 202
        assert response.body == b"custom modified"


@pytest.mark.parametrize(
    "test_case,expected_status,description",
    [
        (
            {
                "max_request_size": 100,
                "headers": Headers(raw=[(b"content-length", b"200")]),
            },
            413,
            "Test route-specific request size limits",
        ),
        (
            {
                "allowed_content_types": ["application/json"],
                "headers": Headers(raw=[(b"content-type", b"text/plain")]),
            },
            415,
            "Test route-specific content type filtering",
        ),
        (
            {
                "custom_validators": [
                    AsyncMock(
                        return_value=StarletteGuardResponse(
                            Response("Custom validation failed", status_code=400)
                        )
                    )
                ],
                "headers": Headers(raw=[]),
            },
            400,
            "Test custom validator returning a Response object",
        ),
        (
            {
                "custom_validators": [AsyncMock(return_value=None)],
                "headers": Headers(raw=[]),
            },
            200,
            "Test custom validator returning None (allows request to proceed)",
        ),
    ],
)
async def test_route_specific_middleware_validations(
    test_case: dict, expected_status: int, description: str
) -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_route_config = RouteConfig()

    for attr, value in test_case.items():
        if attr != "headers":
            setattr(mock_route_config, attr, value)

    mock_request = Request(_http_scope(headers=test_case["headers"].raw))
    mock_request.state.client_ip = "127.0.0.1"

    async def mock_call_next(request: Request) -> Response:
        return Response("ok", status_code=200)

    with patch.object(
        middleware.route_resolver, "get_route_config", return_value=mock_route_config
    ):
        with patch(
            "guard_core.utils.detect_penetration_attempt",
            return_value=DetectionResult(is_threat=False, trigger_info=""),
        ):
            response = await middleware.dispatch(mock_request, mock_call_next)
            assert response.status_code == expected_status


async def test_route_specific_rate_limit_with_redis() -> None:
    app = FastAPI()
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    middleware = SecurityMiddleware(app, config=config)

    mock_redis_handler = Mock()
    middleware.redis_handler = mock_redis_handler

    mock_route_config = RouteConfig()
    mock_route_config.rate_limit = 5
    mock_route_config.rate_limit_window = 60

    mock_request = Request(_http_scope())
    mock_request.state.client_ip = "127.0.0.1"
    mock_request.state.is_whitelisted = False
    mock_request.state.guard_route_id = "app.test"

    async def mock_call_next(request: Request) -> Response:
        return Response("ok", status_code=200)

    with patch.object(
        middleware.route_resolver, "get_route_config", return_value=mock_route_config
    ):
        with patch.object(
            middleware.rate_limit_handler,
            "check_rate_limit",
            new_callable=AsyncMock,
            return_value=None,
        ) as mock_check:
            with patch(
                "guard_core.utils.detect_penetration_attempt",
                return_value=DetectionResult(is_threat=False, trigger_info=""),
            ):
                await middleware.dispatch(mock_request, mock_call_next)
                assert mock_check.call_count >= 2
                route_call = mock_check.call_args_list[0]
                assert route_call[1]["endpoint_path"] == "app.test"
                assert route_call[1]["rate_limit"] == 5
                assert route_call[1]["rate_limit_window"] == 60


async def test_decorator_usage_rules_wrapper_returns_the_throttle_response() -> None:
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=SecurityConfig(enable_redis=False))
    request = Mock()
    request.method = "GET"
    request.state.guard_decorator = None
    request.state.guard_route_id = "test.throttled"
    request.state.guard_exclusion_scoped = False
    route_config = Mock()
    route_config.behavior_rules = [
        BehaviorRule("usage", threshold=1, window=60, action="throttle")
    ]
    first = await middleware._process_decorator_usage_rules(
        request, "127.0.0.1", route_config
    )
    second = await middleware._process_decorator_usage_rules(
        request, "127.0.0.1", route_config
    )
    assert first is None
    assert second is not None and second.status_code == 429
