from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from guard_core.decorators import get_route_id
from guard_core.handlers.behavior_handler import BehaviorRule
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from guard import SecurityConfig, SecurityDecorator
from guard.middleware import SecurityMiddleware


@pytest.fixture
async def behavioral_decorator_app(security_config: SecurityConfig) -> FastAPI:
    """Create FastAPI app with behavioral decorator integration."""
    app = FastAPI()

    security_config.trusted_proxies = ("127.0.0.1",)
    security_config.enable_penetration_detection = False
    security_config.behavior_scan_response_body = True

    decorator = SecurityDecorator(security_config)

    @decorator.usage_monitor(max_calls=5, window=3600, action="ban")
    @app.get("/usage-ban")
    async def usage_ban_endpoint() -> dict[str, str]:
        return {"message": "Usage monitored with ban"}

    @decorator.usage_monitor(max_calls=10, window=300, action="log")
    @app.post("/usage-log")
    async def usage_log_endpoint() -> dict[str, str]:
        return {"message": "Usage monitored with log"}

    @decorator.return_monitor(
        pattern="win", max_occurrences=3, window=86400, action="ban"
    )
    @app.get("/return-win")
    async def return_win_endpoint() -> dict[str, str]:
        return {"message": "win detected", "item": "rare_sword"}

    @decorator.return_monitor(
        pattern="json:result.status==success",
        max_occurrences=5,
        window=3600,
        action="throttle",
    )
    @app.post("/return-json")
    async def return_json_endpoint() -> dict[str, str]:
        return {"message": "success detected", "data": "test"}

    rules = [
        BehaviorRule("usage", threshold=10, window=3600),
        BehaviorRule("return_pattern", threshold=3, pattern="rare", window=86400),
    ]

    @decorator.behavior_analysis(rules)
    @app.get("/behavior-multi")
    async def behavior_multi_endpoint() -> dict[str, str]:
        return {"result": "complex behavior analysis"}

    @decorator.suspicious_frequency(max_frequency=0.1, window=300, action="ban")
    @app.post("/frequency-ban")
    async def frequency_ban_endpoint() -> dict[str, str]:
        return {"result": "frequency monitored"}

    @decorator.suspicious_frequency(max_frequency=2.0, window=60, action="alert")
    @app.get("/frequency-alert")
    async def frequency_alert_endpoint() -> dict[str, str]:
        return {"result": "high frequency allowed"}

    app.add_middleware(SecurityMiddleware, config=security_config)
    app.state.guard_decorator = decorator

    return app


@pytest.mark.parametrize(
    "route_path,expected_rules_count,expected_action,description",
    [
        ("/usage-ban", 1, "ban", "usage_monitor with ban action"),
        ("/usage-log", 1, "log", "usage_monitor with log action"),
        ("/return-win", 1, "ban", "return_monitor with ban action"),
        ("/return-json", 1, "throttle", "return_monitor with throttle action"),
        ("/behavior-multi", 2, None, "behavior_analysis with multiple rules"),
        ("/frequency-ban", 1, "ban", "suspicious_frequency with ban action"),
        ("/frequency-alert", 1, "alert", "suspicious_frequency with alert action"),
    ],
)
async def test_behavioral_decorators_applied(
    behavioral_decorator_app: FastAPI,
    route_path: str,
    expected_rules_count: int,
    expected_action: str | None,
    description: str,
) -> None:
    """Test that behavioral decorators are applied correctly."""
    for route in behavioral_decorator_app.routes:
        if isinstance(route, APIRoute) and route.path == route_path:
            assert hasattr(route.endpoint, "_guard_route_id"), (
                f"{description} should have route ID"
            )

            decorator = behavioral_decorator_app.state.guard_decorator
            route_id = get_route_id(route.endpoint)
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None, f"{description} should have route config"
            assert len(route_config.behavior_rules) == expected_rules_count, (
                f"{description} should have {expected_rules_count} behavior rules"
            )

            if expected_action:
                assert route_config.behavior_rules[0].action == expected_action, (
                    f"{description} should have {expected_action} action"
                )


@pytest.mark.parametrize(
    "route_path,expected_rule_type,expected_threshold,expected_window,description",
    [
        ("/usage-ban", "usage", 5, 3600, "usage_monitor ban configuration"),
        ("/usage-log", "usage", 10, 300, "usage_monitor log configuration"),
        ("/return-win", "return_pattern", 3, 86400, "return_monitor win configuration"),
        (
            "/return-json",
            "return_pattern",
            5,
            3600,
            "return_monitor json configuration",
        ),
        (
            "/frequency-ban",
            "frequency",
            30,
            300,
            "suspicious_frequency ban configuration",
        ),
        (
            "/frequency-alert",
            "frequency",
            120,
            60,
            "suspicious_frequency alert configuration",
        ),
    ],
)
async def test_behavioral_rule_configuration(
    behavioral_decorator_app: FastAPI,
    route_path: str,
    expected_rule_type: str,
    expected_threshold: int,
    expected_window: int,
    description: str,
) -> None:
    """Test that behavioral rule configurations are correct."""
    for route in behavioral_decorator_app.routes:
        if isinstance(route, APIRoute) and route.path == route_path:
            decorator = behavioral_decorator_app.state.guard_decorator
            route_id = get_route_id(route.endpoint)
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None, f"{description} should have route config"
            rule = route_config.behavior_rules[0]

            assert rule.rule_type == expected_rule_type, (
                f"{description} should have {expected_rule_type} rule type"
            )
            assert rule.threshold == expected_threshold, (
                f"{description} should have threshold {expected_threshold}"
            )
            assert rule.window == expected_window, (
                f"{description} should have window {expected_window}"
            )


@pytest.mark.parametrize(
    "route_path,expected_pattern,description",
    [
        ("/return-win", "win", "return_monitor win pattern"),
        ("/return-json", "json:result.status==success", "return_monitor json pattern"),
    ],
)
async def test_return_monitor_patterns(
    behavioral_decorator_app: FastAPI,
    route_path: str,
    expected_pattern: str,
    description: str,
) -> None:
    """Test that return monitor patterns are configured correctly."""
    for route in behavioral_decorator_app.routes:
        if isinstance(route, APIRoute) and route.path == route_path:
            decorator = behavioral_decorator_app.state.guard_decorator
            route_id = get_route_id(route.endpoint)
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None, f"{description} should have route config"
            rule = route_config.behavior_rules[0]

            assert rule.pattern == expected_pattern, (
                f"{description} should have pattern '{expected_pattern}'"
            )


async def test_behavior_analysis_multiple_rules(
    behavioral_decorator_app: FastAPI,
) -> None:
    """Test that behavior_analysis decorator applies multiple rules correctly."""
    for route in behavioral_decorator_app.routes:
        if isinstance(route, APIRoute) and route.path == "/behavior-multi":
            decorator = behavioral_decorator_app.state.guard_decorator
            route_id = get_route_id(route.endpoint)
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None
            assert len(route_config.behavior_rules) == 2

            # Check first rule (usage)
            usage_rule = route_config.behavior_rules[0]
            assert usage_rule.rule_type == "usage"
            assert usage_rule.threshold == 10
            assert usage_rule.window == 3600

            # Check second rule (return_pattern)
            pattern_rule = route_config.behavior_rules[1]
            assert pattern_rule.rule_type == "return_pattern"
            assert pattern_rule.threshold == 3
            assert pattern_rule.pattern == "rare"
            assert pattern_rule.window == 86400


@pytest.mark.parametrize(
    "endpoint,expected_message,description",
    [
        ("/usage-ban", "Usage monitored with ban", "usage_monitor ban endpoint"),
        ("/usage-log", "Usage monitored with log", "usage_monitor log endpoint"),
        ("/return-win", "win detected", "return_monitor win endpoint"),
        ("/return-json", "success detected", "return_monitor json endpoint"),
        ("/behavior-multi", "complex behavior analysis", "behavior_analysis endpoint"),
        ("/frequency-ban", "frequency monitored", "suspicious_frequency ban endpoint"),
        (
            "/frequency-alert",
            "high frequency allowed",
            "suspicious_frequency alert endpoint",
        ),
    ],
)
async def test_behavioral_endpoints_response(
    behavioral_decorator_app: FastAPI,
    endpoint: str,
    expected_message: str,
    description: str,
) -> None:
    """Test calling behavioral endpoints and their responses."""
    async with AsyncClient(
        transport=ASGITransport(app=behavioral_decorator_app), base_url="http://test"
    ) as client:
        method = (
            "post"
            if endpoint in ["/usage-log", "/return-json", "/frequency-ban"]
            else "get"
        )
        response = await getattr(client, method)(
            endpoint, headers={"X-Forwarded-For": "203.0.113.5"}
        )

        assert response.status_code == 200, f"{description} should return 200"
        response_text = response.text
        assert expected_message in response_text, (
            f"{description} should contain '{expected_message}'"
        )


async def test_behavioral_decorators_unit(security_config: SecurityConfig) -> None:
    """Unit tests for behavioral decorators."""
    security_config.behavior_scan_response_body = True
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    # Test usage_monitor
    usage_decorator = decorator.usage_monitor(max_calls=5, window=3600, action="ban")
    decorated_func = usage_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert len(route_config.behavior_rules) == 1
    assert route_config.behavior_rules[0].rule_type == "usage"
    assert route_config.behavior_rules[0].threshold == 5
    assert route_config.behavior_rules[0].window == 3600
    assert route_config.behavior_rules[0].action == "ban"

    # Test return_monitor
    mock_func2 = Mock()
    mock_func2.__name__ = mock_func2.__qualname__ = "test_func2"
    mock_func2.__module__ = "test_module"

    return_decorator = decorator.return_monitor(
        pattern="test_pattern", max_occurrences=3, window=86400, action="log"
    )
    decorated_func2 = return_decorator(mock_func2)

    route_id2 = get_route_id(decorated_func2)
    route_config2 = decorator.get_route_config(route_id2)
    assert route_config2 is not None
    assert len(route_config2.behavior_rules) == 1
    assert route_config2.behavior_rules[0].rule_type == "return_pattern"
    assert route_config2.behavior_rules[0].threshold == 3
    assert route_config2.behavior_rules[0].pattern == "test_pattern"
    assert route_config2.behavior_rules[0].window == 86400
    assert route_config2.behavior_rules[0].action == "log"

    # Test behavior_analysis
    mock_func3 = Mock()
    mock_func3.__name__ = mock_func3.__qualname__ = "test_func3"
    mock_func3.__module__ = "test_module"

    rules = [
        BehaviorRule("usage", threshold=10, window=3600),
        BehaviorRule("return_pattern", threshold=5, pattern="win", window=86400),
    ]
    behavior_decorator = decorator.behavior_analysis(rules)
    decorated_func3 = behavior_decorator(mock_func3)

    route_id3 = get_route_id(decorated_func3)
    route_config3 = decorator.get_route_config(route_id3)
    assert route_config3 is not None
    assert len(route_config3.behavior_rules) == 2
    assert route_config3.behavior_rules[0].rule_type == "usage"
    assert route_config3.behavior_rules[1].rule_type == "return_pattern"

    # Test suspicious_frequency
    mock_func4 = Mock()
    mock_func4.__name__ = mock_func4.__qualname__ = "test_func4"
    mock_func4.__module__ = "test_module"

    frequency_decorator = decorator.suspicious_frequency(
        max_frequency=0.5, window=300, action="throttle"
    )
    decorated_func4 = frequency_decorator(mock_func4)

    route_id4 = get_route_id(decorated_func4)
    route_config4 = decorator.get_route_config(route_id4)
    assert route_config4 is not None
    assert len(route_config4.behavior_rules) == 1
    assert route_config4.behavior_rules[0].rule_type == "frequency"
    assert route_config4.behavior_rules[0].threshold == 150  # 0.5 * 300
    assert route_config4.behavior_rules[0].window == 300
    assert route_config4.behavior_rules[0].action == "throttle"


async def test_return_monitor_body_pattern_without_scan_flag_raises(
    security_config: SecurityConfig,
) -> None:
    decorator = SecurityDecorator(security_config)
    with pytest.raises(ValueError, match="behavior_scan_response_body is False"):
        decorator.return_monitor(
            pattern="win", max_occurrences=3, window=86400, action="ban"
        )
