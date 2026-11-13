import uuid
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.decorators import SecurityDecorator
from guard_core.exceptions import MisconfigurationError
from guard_core.handlers.ipban_handler import ip_ban_manager, ip_ban_manager_for
from guard_core.models import SecurityConfig

from guard._middleware_state import get_state
from guard.asgi import PureASGISecurityMiddleware
from guard.middleware import SecurityMiddleware
from tests.redis_isolation import REDIS_URL, suite_redis_prefix

PEER = ("203.0.113.9", 50000)


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "rate_limit": 1000,
        "enable_penetration_detection": False,
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


def _app(
    config: SecurityConfig,
    decorator: SecurityDecorator,
    middleware: Any = SecurityMiddleware,
) -> FastAPI:
    app = FastAPI()

    @app.get("/r/")
    @decorator.require_headers({"X-Need": "required"})
    async def guarded() -> dict[str, str]:
        return {"ok": "reached"}

    @app.get("/plain/")
    async def plain() -> dict[str, str]:
        return {"ok": "plain"}

    @app.get("/counted/")
    @decorator.usage_monitor(max_calls=1, window=60, action="ban")
    async def counted() -> dict[str, str]:
        return {"ok": "counted"}

    app.add_middleware(middleware, config=config)
    return app


def _live(app: FastAPI) -> SecurityMiddleware:
    node = app.middleware_stack
    while node is not None:
        if isinstance(node, SecurityMiddleware):
            return node
        if isinstance(node, PureASGISecurityMiddleware):
            return node._engine
        node = getattr(node, "app", None)
    raise AssertionError("no guard middleware in the built stack")


def _build(app: FastAPI) -> SecurityMiddleware:
    app.middleware_stack = app.build_middleware_stack()
    return _live(app)


async def _get(app: FastAPI, path: str, headers: dict[str, str] | None = None) -> int:
    transport = httpx.ASGITransport(app=app, client=PEER)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        return (await client.get(path, headers=headers)).status_code


@pytest.mark.parametrize("form", [SecurityMiddleware, PureASGISecurityMiddleware])
@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("no_decorator", (200, 200)),
        ("state_only", (400, 200)),
        ("setter_before_init", (400, 200)),
        ("setter_after_init", (400, 200)),
    ],
)
def test_a_decorator_given_by_the_setter_reaches_the_route_resolver(
    form: Any, case: str, expected: tuple[int, int]
) -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    app = _app(config, decorator, form)
    if case == "state_only":
        app.state.guard_decorator = decorator
    client = TestClient(app, client=PEER)
    if case == "setter_before_init":
        _build(app).set_decorator_handler(decorator)
    assert client.get("/plain/").status_code == 200
    if case == "setter_after_init":
        _live(app).set_decorator_handler(decorator)

    got = (
        client.get("/r/").status_code,
        client.get("/r/", headers={"X-Need": "required"}).status_code,
    )

    assert got == expected


def test_a_setter_before_the_lifespan_is_not_replaced_by_the_empty_app_state() -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    app = _app(config, decorator)
    _build(app).set_decorator_handler(decorator)

    with TestClient(app, client=PEER) as client:
        status = client.get("/r/").status_code

    assert status == 400


def test_the_shared_state_follows_the_decorator_the_setter_gave() -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    app = _app(config, decorator)
    client = TestClient(app, client=PEER)
    client.get("/plain/")
    middleware = _live(app)
    assert get_state(config, None, app) is not None

    middleware.set_decorator_handler(decorator)
    client.get("/plain/")

    found = get_state(config, decorator, app)
    assert found is not None
    assert found.security_pipeline is middleware.security_pipeline
    assert get_state(config, None, app) is None


async def test_a_ban_rule_of_a_late_decorator_bans_on_the_apps_ban_manager() -> None:
    first = _config()
    assert await _get(_app(first, SecurityDecorator(first)), "/plain/") == 200
    config = _config()
    decorator = SecurityDecorator(SecurityConfig())
    app = _app(config, decorator)
    assert await _get(app, "/plain/") == 200
    apps_manager = ip_ban_manager_for(config)
    assert apps_manager is not ip_ban_manager
    _live(app).set_decorator_handler(decorator)

    statuses = [await _get(app, "/counted/") for _ in range(3)]

    assert statuses[0] == 200
    assert await apps_manager.is_ip_banned(PEER[0])
    assert decorator.behavior_tracker.bound_ban_manager is apps_manager


async def test_a_late_decorators_rule_counts_on_the_decorators_tracker_only() -> None:
    config = _config()
    decorator = SecurityDecorator(SecurityConfig())
    app = _app(config, decorator)
    assert await _get(app, "/plain/") == 200
    middleware = _live(app)
    middleware.set_decorator_handler(decorator)

    assert await _get(app, "/counted/") == 200

    held = middleware.handler_initializer.behavior_tracker
    assert middleware.behavioral_processor.context.behavior_tracker is held
    assert held in (None, decorator.behavior_tracker)
    assert any(decorator.behavior_tracker.usage_counts.values())


async def test_a_late_decorators_tracker_gets_redis_once_a_request_completed_it() -> (
    None
):
    config = _config(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=suite_redis_prefix(f"wp779{uuid.uuid4().hex[:8]}"),
    )
    decorator = SecurityDecorator(SecurityConfig())
    app = _app(config, decorator)
    assert await _get(app, "/plain/") == 200
    middleware = _live(app)
    middleware.set_decorator_handler(decorator)
    tracker = decorator.behavior_tracker
    assert tracker.redis_handler is None

    assert await _get(app, "/plain/") == 200

    assert tracker.redis_handler is middleware.handler_initializer.redis_handler
    assert tracker.redis_handler is not None


async def test_a_route_country_rule_of_a_late_decorator_builds_the_geo_handler() -> (
    None
):
    config = _config(ipinfo_token="test_token")
    decorator = SecurityDecorator(SecurityConfig(fail_on_misconfiguration=False))

    app = _app(config, decorator)

    @app.get("/by-country/")
    @decorator.block_countries(["XX"])
    async def by_country() -> dict[str, str]:
        return {"ok": "country"}

    assert await _get(app, "/plain/") == 200
    middleware = _live(app)
    before = middleware.geo_ip_handler

    middleware.set_decorator_handler(decorator)

    assert before is None
    assert middleware.geo_ip_handler is middleware.handler_initializer.geo_ip_handler
    assert middleware.geo_ip_handler is not None


async def test_a_raise_in_the_adoption_leaves_the_previous_decorator_bound() -> None:
    config = _config()
    previous = SecurityDecorator(config)
    app = _app(config, previous)
    assert await _get(app, "/plain/") == 200
    middleware = _live(app)
    middleware.set_decorator_handler(previous)
    candidate = SecurityDecorator(SecurityConfig(fail_on_misconfiguration=False))

    @candidate.block_countries(["XX"])
    async def by_country() -> None:
        return None

    candidate.config.fail_on_misconfiguration = True

    with pytest.raises(MisconfigurationError):
        middleware.set_decorator_handler(candidate)

    assert middleware.guard_decorator is previous
    assert middleware.handler_initializer.guard_decorator is previous
    assert middleware.route_resolver.context.guard_decorator is previous
    assert middleware.response_factory.context.guard_decorator is previous
    assert middleware.behavioral_processor.context.guard_decorator is previous
