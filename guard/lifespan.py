from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import TypeVar, overload

from guard_core._utils.config_registry import REDIS_HANDLERS
from guard_core.exceptions import GuardRedisError
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig

from guard._decorator_adoption import resolve_app_state_decorator
from guard._middleware_state import MiddlewareState, get_state, register_state
from guard.middleware import SecurityMiddleware

AppT = TypeVar("AppT")


def _find_security_middleware(app: object) -> SecurityMiddleware | None:
    user_middleware = getattr(app, "user_middleware", None)
    if not user_middleware:
        return None
    for entry in user_middleware:
        if getattr(entry, "cls", None) is SecurityMiddleware:
            kwargs = getattr(entry, "kwargs", None)
            if kwargs is None:
                kwargs = getattr(entry, "options", {})
            try:
                built: SecurityMiddleware = entry.cls(app, **kwargs)
                return built
            except Exception:
                return None
    return None


def _find_security_config(app: object) -> SecurityConfig | None:
    user_middleware = getattr(app, "user_middleware", None)
    if not user_middleware:
        return None
    for entry in user_middleware:
        cls = getattr(entry, "cls", None)
        if cls is SecurityMiddleware:
            kwargs = getattr(entry, "kwargs", None)
            if kwargs is None:
                kwargs = getattr(entry, "options", {})
            config = kwargs.get("config")
            if isinstance(config, SecurityConfig):
                return config
            return None
    return None


def _find_security_redis_handler(app: object) -> RedisManager | None:
    config = _find_security_config(app)
    if config is None or not config.enable_redis:
        return None
    handler = REDIS_HANDLERS.lookup(config)
    if isinstance(handler, RedisManager) and handler._redis is not None:
        return handler
    return None


def _built_security_middleware(app: object) -> SecurityMiddleware | None:
    node = getattr(app, "middleware_stack", None)
    while node is not None:
        if isinstance(node, SecurityMiddleware):
            return node
        node = getattr(node, "app", None)
    return None


def _cold_security_middleware(app: object) -> SecurityMiddleware | None:
    state = getattr(app, "state", None)
    kept = getattr(state, "_guard_cold_security_middleware", None)
    if isinstance(kept, SecurityMiddleware):
        return kept
    built = _find_security_middleware(app)
    if built is not None and state is not None:
        state._guard_cold_security_middleware = built
    return built


async def initialize_like_http_if_cold(app: object, config: SecurityConfig) -> None:
    decorator = resolve_app_state_decorator(app)
    if get_state(config, decorator) is not None:
        return
    middleware = _built_security_middleware(app) or _cold_security_middleware(app)
    if middleware is None:
        return
    if middleware.guard_decorator is None:
        middleware.guard_decorator = decorator
    await middleware._ensure_initialized()


def _register_state_from_middleware(
    middleware: SecurityMiddleware, app: object
) -> None:
    register_state(
        middleware.config,
        middleware.guard_decorator,
        MiddlewareState(
            security_pipeline=middleware.security_pipeline,
            composite_handler=middleware.handler_initializer.composite_handler,
            event_bus=middleware.event_bus,
            metrics_collector=middleware.metrics_collector,
            response_factory=middleware.response_factory,
            validator=middleware.validator,
            bypass_handler=middleware.bypass_handler,
            behavioral_processor=middleware.behavioral_processor,
            handler_initializer=middleware.handler_initializer,
            agent_handler=middleware.agent_handler,
        ),
        app,
    )


async def _warm_middleware_or_adopt(
    middleware: SecurityMiddleware, app: object
) -> None:
    middleware.guard_decorator = resolve_app_state_decorator(app)
    middleware._routing_app = app
    warm = get_state(middleware.config, middleware.guard_decorator, app)
    if warm is not None:
        middleware._adopt_warm_state(warm)
        middleware.mark_initialized()
        return
    try:
        await middleware.initialize()
    except GuardRedisError as e:
        middleware.logger.error(
            "Redis unavailable during startup initialization: %s; the first "
            "request will retry and return 503 until Redis is reachable",
            e,
        )
        return
    middleware.mark_initialized()
    _register_state_from_middleware(middleware, app)


async def _release_redis_hold(app: object) -> None:
    handler = _find_security_redis_handler(app)
    if handler is not None:
        await handler.close()


@asynccontextmanager
async def guard_lifespan(app: object) -> AsyncIterator[None]:
    middleware = _find_security_middleware(app)
    if middleware is not None:
        await _warm_middleware_or_adopt(middleware, app)
    try:
        yield
    finally:
        await _release_redis_hold(app)


async def guard_startup(app: object) -> None:
    middleware = _find_security_middleware(app)
    if middleware is not None:
        await _warm_middleware_or_adopt(middleware, app)


@overload
def make_lifespan(
    existing_lifespan: None = None,
) -> Callable[[object], AbstractAsyncContextManager[None]]: ...


@overload
def make_lifespan(
    existing_lifespan: Callable[[AppT], AbstractAsyncContextManager[None]],
) -> Callable[[AppT], AbstractAsyncContextManager[None]]: ...


@overload
def make_lifespan(
    existing_lifespan: Callable[
        [AppT], AbstractAsyncContextManager[Mapping[str, object]]
    ],
) -> Callable[[AppT], AbstractAsyncContextManager[Mapping[str, object]]]: ...


def make_lifespan(
    existing_lifespan: Callable[
        [AppT], AbstractAsyncContextManager[Mapping[str, object] | None]
    ]
    | None = None,
) -> Callable[[AppT], AbstractAsyncContextManager[Mapping[str, object] | None]]:
    @asynccontextmanager
    async def combined(app: AppT) -> AsyncIterator[Mapping[str, object] | None]:
        middleware = _find_security_middleware(app)
        if middleware is not None:
            await _warm_middleware_or_adopt(middleware, app)
        try:
            if existing_lifespan is not None:
                async with existing_lifespan(app) as state:
                    yield state
            else:
                yield None
        finally:
            await _release_redis_hold(app)

    return combined
