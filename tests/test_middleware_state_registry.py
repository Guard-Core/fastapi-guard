from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.models import SecurityConfig
from starlette.requests import Request

from guard._middleware_state import (
    clear_state_registry,
    get_state,
)
from guard.lifespan import guard_lifespan, guard_startup, make_lifespan
from guard.middleware import SecurityMiddleware


def _request_scoped_to(app: FastAPI, path: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "query_string": b"",
            "headers": [],
            "server": ("localhost", 8000),
            "root_path": "",
            "state": {},
            "app": app,
        }
    )


@pytest.fixture(autouse=True)
def _clear_registry_between_tests() -> Iterator[None]:
    clear_state_registry()
    yield
    clear_state_registry()


@pytest.fixture(autouse=True)
def _clear_singleton_redis_handlers() -> None:
    from guard_core.handlers.cloud_handler import cloud_handler
    from guard_core.handlers.ipban_handler import ip_ban_manager
    from guard_core.handlers.ratelimit_handler import rate_limit_handler
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler

    ip_ban_manager.redis_handler = None
    sus_patterns_handler.redis_handler = None
    rate_limit_handler.redis_handler = None
    if cloud_handler._instance is not None:
        cloud_handler._instance.redis_handler = None


def test_same_config_shares_state_across_instances() -> None:
    config = SecurityConfig(enable_redis=False)
    app1 = FastAPI(lifespan=guard_lifespan)
    app1.add_middleware(SecurityMiddleware, config=config)

    @app1.get("/health")
    async def h1() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app1, client=("127.0.0.1", 12345)) as client:
        client.get("/health")

        state = get_state(config)
        assert state is not None
        assert state.security_pipeline is not None

        app2 = FastAPI(lifespan=guard_lifespan)
        app2.add_middleware(SecurityMiddleware, config=config)

        @app2.get("/health")
        async def h2() -> dict[str, bool]:
            return {"ok": True}

        state_before = get_state(config)
        with TestClient(app2, client=("127.0.0.1", 12345)) as client2:
            client2.get("/health")
            state_after = get_state(config)

        assert state_before is state_after
        assert state_before is not None
        assert state_after is not None
        assert state_before.security_pipeline is state_after.security_pipeline


def test_different_configs_get_different_state_entries() -> None:
    config_a = SecurityConfig(enable_redis=False)
    config_b = SecurityConfig(enable_redis=False, rate_limit=999)

    app_a = FastAPI(lifespan=guard_lifespan)
    app_a.add_middleware(SecurityMiddleware, config=config_a)

    @app_a.get("/health")
    async def ha() -> dict[str, bool]:
        return {"ok": True}

    app_b = FastAPI(lifespan=guard_lifespan)
    app_b.add_middleware(SecurityMiddleware, config=config_b)

    @app_b.get("/health")
    async def hb() -> dict[str, bool]:
        return {"ok": True}

    with (
        TestClient(app_a, client=("127.0.0.1", 12345)) as ca,
        TestClient(app_b, client=("127.0.0.1", 12345)) as cb,
    ):
        ca.get("/health")
        cb.get("/health")

        state_a = get_state(config_a)
        state_b = get_state(config_b)
        assert state_a is not None
        assert state_b is not None
        assert state_a is not state_b


def test_composite_handler_start_called_exactly_once_per_config() -> None:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI(lifespan=guard_lifespan)
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    start_calls: list[object] = []

    from guard_core.core.events.composite_handler import CompositeAgentHandler

    original_start = CompositeAgentHandler.start

    async def tracking_start(
        self: CompositeAgentHandler, *args: object, **kwargs: object
    ) -> None:
        start_calls.append(self)
        await original_start(self, *args, **kwargs)

    with patch.object(CompositeAgentHandler, "start", tracking_start):
        with TestClient(app, client=("127.0.0.1", 12345)) as client:
            client.get("/health")
            client.get("/health")

    assert len(start_calls) <= 1


def test_lifespan_populates_registry_before_first_request() -> None:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI(lifespan=guard_lifespan)
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    assert get_state(config) is None

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        state_at_startup = get_state(config)
        assert state_at_startup is not None

        client.get("/health")
        state_after_request = get_state(config)
        assert state_after_request is state_at_startup


def test_no_lifespan_still_works_via_lazy_fallback() -> None:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    assert get_state(config) is None

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        resp = client.get("/health")
        assert resp.status_code == 200

    assert get_state(config) is not None


def test_clear_state_registry_empties_it() -> None:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI(lifespan=guard_lifespan)
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        client.get("/health")

        assert get_state(config) is not None
        clear_state_registry()
        assert get_state(config) is None


def test_make_lifespan_also_populates_registry() -> None:
    config = SecurityConfig(enable_redis=False)

    @asynccontextmanager
    async def existing(app: FastAPI) -> AsyncIterator[None]:
        yield

    app = FastAPI(lifespan=make_lifespan(existing))
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        client.get("/health")

        assert get_state(config) is not None


def test_adopt_warm_state_prefers_composite_handler() -> None:
    from guard._middleware_state import MiddlewareState

    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)
    middleware = SecurityMiddleware(app, config=config)

    sentinel_composite = MagicMock()
    sentinel_agent = MagicMock()
    state = MiddlewareState(
        security_pipeline=MagicMock(),
        composite_handler=sentinel_composite,
        event_bus=MagicMock(),
        metrics_collector=MagicMock(),
        response_factory=MagicMock(),
        validator=MagicMock(),
        bypass_handler=MagicMock(),
        behavioral_processor=MagicMock(),
        handler_initializer=MagicMock(),
        agent_handler=sentinel_agent,
    )
    middleware._adopt_warm_state(state)
    assert middleware.agent_handler is sentinel_composite


def test_adopt_warm_state_falls_back_to_agent_handler() -> None:
    from guard._middleware_state import MiddlewareState

    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)
    middleware = SecurityMiddleware(app, config=config)

    sentinel_agent = MagicMock()
    state = MiddlewareState(
        security_pipeline=MagicMock(),
        composite_handler=None,
        event_bus=MagicMock(),
        metrics_collector=MagicMock(),
        response_factory=MagicMock(),
        validator=MagicMock(),
        bypass_handler=MagicMock(),
        behavioral_processor=MagicMock(),
        handler_initializer=MagicMock(),
        agent_handler=sentinel_agent,
    )
    middleware._adopt_warm_state(state)
    assert middleware.agent_handler is sentinel_agent


def test_adopt_warm_state_leaves_agent_handler_when_both_none() -> None:
    from guard._middleware_state import MiddlewareState

    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)
    middleware = SecurityMiddleware(app, config=config)
    previous_agent = middleware.agent_handler

    state = MiddlewareState(
        security_pipeline=MagicMock(),
        composite_handler=None,
        event_bus=MagicMock(),
        metrics_collector=MagicMock(),
        response_factory=MagicMock(),
        validator=MagicMock(),
        bypass_handler=MagicMock(),
        behavioral_processor=MagicMock(),
        handler_initializer=MagicMock(),
        agent_handler=None,
    )
    middleware._adopt_warm_state(state)
    assert middleware.agent_handler is previous_agent


def test_warm_adoption_uses_same_object_references() -> None:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI(lifespan=guard_lifespan)
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        client.get("/health")

        state = get_state(config)
        assert state is not None
        assert state.security_pipeline is not None
        assert state.handler_initializer is not None
        assert state.validator is not None
        assert state.response_factory is not None
        assert state.bypass_handler is not None
        assert state.behavioral_processor is not None


async def test_guard_startup_initializes_with_no_lifespan_wired() -> None:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    assert get_state(config) is None

    await guard_startup(app)

    state = get_state(config)
    assert state is not None
    assert state.security_pipeline is not None
    assert state.handler_initializer is not None


async def test_guard_startup_no_middleware_no_ops() -> None:
    app = FastAPI()
    await guard_startup(app)


async def test_guard_startup_is_idempotent() -> None:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    initialize_calls: list[SecurityMiddleware] = []
    original_initialize = SecurityMiddleware.initialize

    async def tracking_initialize(self: SecurityMiddleware) -> None:
        initialize_calls.append(self)
        await original_initialize(self)

    with patch.object(SecurityMiddleware, "initialize", tracking_initialize):
        await guard_startup(app)
        await guard_startup(app)
        await guard_startup(app)

    assert len(initialize_calls) == 1


async def test_guard_startup_matches_guard_lifespan_state_shape() -> None:
    config_direct = SecurityConfig(enable_redis=False)
    app_direct = FastAPI()
    app_direct.add_middleware(SecurityMiddleware, config=config_direct)
    await guard_startup(app_direct)
    state_direct = get_state(config_direct)

    config_lifespan = SecurityConfig(enable_redis=False)
    app_lifespan = FastAPI(lifespan=guard_lifespan)
    app_lifespan.add_middleware(SecurityMiddleware, config=config_lifespan)
    async with guard_lifespan(app_lifespan):
        state_lifespan = get_state(config_lifespan)

    assert state_direct is not None
    assert state_lifespan is not None
    for field in (
        "security_pipeline",
        "event_bus",
        "metrics_collector",
        "response_factory",
        "validator",
        "bypass_handler",
        "behavioral_processor",
        "handler_initializer",
    ):
        direct_value = getattr(state_direct, field)
        lifespan_value = getattr(state_lifespan, field)
        assert direct_value is not None
        assert lifespan_value is not None
        assert type(direct_value) is type(lifespan_value)


async def test_second_middleware_with_different_decorator_builds_own_pipeline() -> None:
    from guard import SecurityDecorator

    config = SecurityConfig(enable_redis=False)

    app_a = FastAPI()
    decorator_a = SecurityDecorator(config)

    @decorator_a.rate_limit(requests=10, window=60)
    @app_a.get("/rate-limited")
    async def rate_limited() -> dict[str, bool]:
        return {"ok": True}

    app_a.state.guard_decorator = decorator_a
    middleware_a = SecurityMiddleware(app_a, config=config)

    app_b = FastAPI()
    decorator_b = SecurityDecorator(config)

    @decorator_b.require_auth()
    @app_b.get("/needs-auth")
    async def needs_auth() -> dict[str, bool]:
        return {"ok": True}

    app_b.state.guard_decorator = decorator_b
    middleware_b = SecurityMiddleware(app_b, config=config)

    await middleware_a._ensure_initialized(_request_scoped_to(app_a, "/rate-limited"))
    await middleware_b._ensure_initialized(_request_scoped_to(app_b, "/needs-auth"))

    assert middleware_a.security_pipeline is not None
    assert middleware_b.security_pipeline is not None
    check_names_a = set(middleware_a.security_pipeline.get_check_names())
    check_names_b = set(middleware_b.security_pipeline.get_check_names())

    assert "authentication" not in check_names_a
    assert "authentication" in check_names_b


async def test_guard_lifespan_adopts_app_state_decorator_before_building_pipeline() -> (
    None
):
    from guard import SecurityDecorator

    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    decorator = SecurityDecorator(config)

    @decorator.rate_limit(requests=10, window=60)
    @app.get("/rate-limited")
    async def rate_limited() -> dict[str, bool]:
        return {"ok": True}

    app.state.guard_decorator = decorator
    middleware = SecurityMiddleware(app, config=config)

    with patch("guard.lifespan._find_security_middleware", return_value=middleware):
        async with guard_lifespan(app):
            pass

    assert middleware.guard_decorator is decorator
    assert middleware.security_pipeline is not None
    check_names = set(middleware.security_pipeline.get_check_names())
    assert "rate_limit" in check_names
    assert "authentication" not in check_names
