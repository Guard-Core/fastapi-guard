from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from guard_core.handlers.cloud_handler import cloud_handler_for
from guard_core.models import SecurityConfig

from guard import SecurityDecorator
from guard._middleware_state import MiddlewareState, register_state
from guard.lifespan import (
    _built_security_middleware,
    _cold_security_middleware,
    initialize_like_http_if_cold,
)
from guard.middleware import SecurityMiddleware


def _app_with_middleware(config: SecurityConfig) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)
    return app


def test_built_middleware_is_none_when_the_stack_has_no_security_middleware() -> None:
    stack = SimpleNamespace(app=SimpleNamespace(app=None))

    assert _built_security_middleware(SimpleNamespace(middleware_stack=stack)) is None


def test_cold_middleware_is_built_once_and_kept_on_app_state() -> None:
    app = _app_with_middleware(SecurityConfig(enable_redis=False))

    first = _cold_security_middleware(app)
    second = _cold_security_middleware(app)

    assert first is not None
    assert second is first
    assert app.state._guard_cold_security_middleware is first


def test_cold_middleware_is_none_without_a_registered_security_middleware() -> None:
    assert _cold_security_middleware(FastAPI()) is None


async def test_initialization_is_skipped_when_a_warm_state_exists() -> None:
    config = SecurityConfig(enable_redis=False)
    app = _app_with_middleware(config)
    register_state(config, None, _a_state())

    await initialize_like_http_if_cold(app, config)

    assert not hasattr(app.state, "_guard_cold_security_middleware")


async def test_initialization_is_skipped_without_any_security_middleware() -> None:
    await initialize_like_http_if_cold(FastAPI(), SecurityConfig(enable_redis=False))


async def test_the_cold_middleware_adopts_the_decorator_from_app_state() -> None:
    config = SecurityConfig(enable_redis=False)
    app = _app_with_middleware(config)
    decorator = SecurityDecorator(config)
    app.state.guard_decorator = decorator

    await initialize_like_http_if_cold(app, config)

    cold = app.state._guard_cold_security_middleware
    assert cold.guard_decorator is decorator
    assert cold._is_initialized()


async def test_the_cold_middleware_keeps_a_decorator_it_already_holds() -> None:
    config = SecurityConfig(enable_redis=False)
    app = _app_with_middleware(config)
    own = SecurityDecorator(config)
    cold = _cold_security_middleware(app)
    assert cold is not None
    cold.set_decorator_handler(own)

    await initialize_like_http_if_cold(app, config)

    assert cold.guard_decorator is own
    assert cold._is_initialized()


async def test_cloud_refresh_without_redis_refreshes_the_listed_providers() -> None:
    config = SecurityConfig(
        enable_redis=False, block_cloud_providers=frozenset({"AWS"})
    )
    middleware = SecurityMiddleware(FastAPI(), config=config)

    with patch.object(
        cloud_handler_for(config, bind=True), "refresh", new_callable=AsyncMock
    ) as refresh:
        await middleware.refresh_cloud_ip_ranges()

    refresh.assert_awaited_once_with({"AWS"})
    assert middleware.last_cloud_ip_refresh > 0


async def test_cloud_refresh_with_redis_uses_the_shared_refresh_and_ttl() -> None:
    config = SecurityConfig(
        enable_redis=True,
        redis_url="redis://127.0.0.1:1/12",
        block_cloud_providers=frozenset({"AWS"}),
        cloud_ip_refresh_interval=900,
    )
    middleware = SecurityMiddleware(FastAPI(), config=config)

    with patch.object(
        cloud_handler_for(config, bind=True), "refresh_async", new_callable=AsyncMock
    ) as refresh_async:
        await middleware.refresh_cloud_ip_ranges()

    refresh_async.assert_awaited_once_with({"AWS"}, ttl=900)


def _a_state() -> MiddlewareState:
    return MiddlewareState(
        security_pipeline=None,
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
