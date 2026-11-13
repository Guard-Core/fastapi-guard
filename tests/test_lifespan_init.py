from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from guard_core.models import SecurityConfig
from starlette.middleware import Middleware

from guard.lifespan import (
    _find_security_config,
    _find_security_middleware,
    guard_lifespan,
    make_lifespan,
)
from guard.middleware import SecurityMiddleware


@pytest.fixture
def fastapi_app_with_middleware() -> FastAPI:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)
    return app


@pytest.mark.asyncio
async def test_guard_lifespan_initializes_and_marks(
    fastapi_app_with_middleware: FastAPI,
) -> None:
    app = fastapi_app_with_middleware

    middleware = MagicMock(spec=SecurityMiddleware)
    middleware.config = SecurityConfig(enable_redis=False)
    middleware.initialize = AsyncMock()
    middleware.mark_initialized = MagicMock()
    middleware.handler_initializer = MagicMock(composite_handler=None)
    middleware.security_pipeline = MagicMock()
    middleware.event_bus = MagicMock()
    middleware.metrics_collector = MagicMock()
    middleware.response_factory = MagicMock()
    middleware.validator = MagicMock()
    middleware.bypass_handler = MagicMock()
    middleware.behavioral_processor = MagicMock()
    middleware.agent_handler = None
    middleware.guard_decorator = None

    with patch("guard.lifespan._find_security_middleware", return_value=middleware):
        async with guard_lifespan(app):
            pass

    middleware.initialize.assert_awaited_once()
    middleware.mark_initialized.assert_called_once()


@pytest.mark.asyncio
async def test_guard_lifespan_no_middleware_yields_silently() -> None:
    app = FastAPI()
    async with guard_lifespan(app):
        pass


@pytest.mark.asyncio
async def test_make_lifespan_runs_existing_lifespan() -> None:
    existing_calls: list[str] = []

    @asynccontextmanager
    async def existing(app: FastAPI) -> AsyncIterator[None]:
        existing_calls.append("enter")
        yield
        existing_calls.append("exit")

    app = FastAPI()
    combined = make_lifespan(existing)
    async with combined(app):
        pass

    assert existing_calls == ["enter", "exit"]


@pytest.mark.asyncio
async def test_make_lifespan_initializes_then_runs_existing() -> None:
    existing_calls: list[str] = []

    @asynccontextmanager
    async def existing(app: FastAPI) -> AsyncIterator[None]:
        existing_calls.append("enter")
        yield

    middleware = MagicMock(spec=SecurityMiddleware)
    middleware.config = SecurityConfig(enable_redis=False)
    middleware.initialize = AsyncMock()
    middleware.mark_initialized = MagicMock()
    middleware.handler_initializer = MagicMock(composite_handler=None)
    middleware.security_pipeline = MagicMock()
    middleware.event_bus = MagicMock()
    middleware.metrics_collector = MagicMock()
    middleware.response_factory = MagicMock()
    middleware.validator = MagicMock()
    middleware.bypass_handler = MagicMock()
    middleware.behavioral_processor = MagicMock()
    middleware.agent_handler = None
    middleware.guard_decorator = None

    app = FastAPI()
    combined = make_lifespan(existing)

    with patch("guard.lifespan._find_security_middleware", return_value=middleware):
        async with combined(app):
            pass

    middleware.initialize.assert_awaited_once()
    middleware.mark_initialized.assert_called_once()
    assert existing_calls == ["enter"]


@pytest.mark.asyncio
async def test_make_lifespan_no_existing_lifespan() -> None:
    middleware = MagicMock(spec=SecurityMiddleware)
    middleware.config = SecurityConfig(enable_redis=False)
    middleware.initialize = AsyncMock()
    middleware.mark_initialized = MagicMock()
    middleware.handler_initializer = MagicMock(composite_handler=None)
    middleware.security_pipeline = MagicMock()
    middleware.event_bus = MagicMock()
    middleware.metrics_collector = MagicMock()
    middleware.response_factory = MagicMock()
    middleware.validator = MagicMock()
    middleware.bypass_handler = MagicMock()
    middleware.behavioral_processor = MagicMock()
    middleware.agent_handler = None
    middleware.guard_decorator = None

    app = FastAPI()
    combined = make_lifespan(None)

    with patch("guard.lifespan._find_security_middleware", return_value=middleware):
        async with combined(app):
            pass

    middleware.initialize.assert_awaited_once()


@pytest.mark.asyncio
async def test_find_security_middleware_returns_instance() -> None:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    instance = _find_security_middleware(app)
    assert instance is not None
    assert isinstance(instance, SecurityMiddleware)


@pytest.mark.asyncio
async def test_find_security_middleware_returns_none_when_absent() -> None:
    app = FastAPI()
    instance = _find_security_middleware(app)
    assert instance is None


@pytest.mark.asyncio
async def test_find_security_middleware_skips_other_middleware() -> None:
    from starlette.middleware.cors import CORSMiddleware

    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    app.add_middleware(CORSMiddleware, allow_origins=["*"])
    app.add_middleware(SecurityMiddleware, config=config)

    instance = _find_security_middleware(app)
    assert isinstance(instance, SecurityMiddleware)


@pytest.mark.asyncio
async def test_find_security_middleware_returns_none_with_only_other_middleware() -> (
    None
):
    from starlette.middleware.cors import CORSMiddleware

    app = FastAPI()
    app.add_middleware(CORSMiddleware, allow_origins=["*"])

    instance = _find_security_middleware(app)
    assert instance is None


@pytest.mark.asyncio
async def test_find_security_middleware_returns_none_when_user_middleware_missing() -> (
    None
):
    class FakeApp:
        pass

    instance = _find_security_middleware(FakeApp())
    assert instance is None


@pytest.mark.asyncio
async def test_find_security_middleware_falls_back_to_options_attr() -> None:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI()

    class LegacyEntry:
        cls = SecurityMiddleware
        kwargs = None
        options = {"config": config}

    app.user_middleware = cast(list[Middleware], [LegacyEntry()])

    instance = _find_security_middleware(app)
    assert isinstance(instance, SecurityMiddleware)


@pytest.mark.asyncio
async def test_find_security_middleware_raises_what_the_constructor_raises() -> None:
    app = FastAPI()

    class BrokenEntry:
        cls = SecurityMiddleware
        kwargs: dict[str, Any] = {"config": "not-a-valid-config"}

    app.user_middleware = cast(list[Middleware], [BrokenEntry()])

    with pytest.raises(AttributeError, match="custom_log_file"):
        _find_security_middleware(app)


@pytest.mark.asyncio
async def test_find_security_config_returns_none_when_user_middleware_missing() -> None:
    class FakeApp:
        pass

    config = _find_security_config(FakeApp())
    assert config is None


@pytest.mark.asyncio
async def test_find_security_config_returns_none_with_only_other_middleware() -> None:
    from starlette.middleware.cors import CORSMiddleware

    app = FastAPI()
    app.add_middleware(CORSMiddleware, allow_origins=["*"])

    config = _find_security_config(app)
    assert config is None


@pytest.mark.asyncio
async def test_find_security_config_skips_other_middleware() -> None:
    from starlette.middleware.cors import CORSMiddleware

    expected_config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    app.add_middleware(CORSMiddleware, allow_origins=["*"])
    app.add_middleware(SecurityMiddleware, config=expected_config)

    config = _find_security_config(app)
    assert config is expected_config


@pytest.mark.asyncio
async def test_find_security_config_falls_back_to_options_attr() -> None:
    expected_config = SecurityConfig(enable_redis=False)
    app = FastAPI()

    class LegacyEntry:
        cls = SecurityMiddleware
        kwargs = None
        options = {"config": expected_config}

    app.user_middleware = cast(list[Middleware], [LegacyEntry()])

    config = _find_security_config(app)
    assert config is expected_config


@pytest.mark.asyncio
async def test_find_security_config_returns_none_for_non_security_config_value() -> (
    None
):
    app = FastAPI()

    class BrokenEntry:
        cls = SecurityMiddleware
        kwargs: dict[str, Any] = {"config": "not-a-valid-config"}

    app.user_middleware = cast(list[Middleware], [BrokenEntry()])

    config = _find_security_config(app)
    assert config is None
