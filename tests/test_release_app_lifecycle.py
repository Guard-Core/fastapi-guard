from __future__ import annotations

import asyncio
import gc
import threading
from collections.abc import Callable, Iterator
from contextlib import AbstractAsyncContextManager

import pytest
from fastapi import FastAPI
from guard_core import release_app
from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.models import SecurityConfig

from guard import lifespan as lifespan_module
from guard._middleware_state import get_state
from guard.lifespan import guard_lifespan, make_lifespan
from guard.middleware import SecurityMiddleware

_IP = "203.0.113.7"


def _config() -> SecurityConfig:
    return SecurityConfig(enable_redis=False)


def _app(
    config: SecurityConfig,
    lifespan: Callable[[object], AbstractAsyncContextManager[None]] = guard_lifespan,
) -> FastAPI:
    app = FastAPI(lifespan=lifespan)
    app.add_middleware(SecurityMiddleware, config=config)
    return app


def _default_serves_a_new_app() -> bool:
    probe = _config()
    served = ip_ban_manager_for(probe, bind=True) is ipban_module.ip_ban_manager
    release_app(probe)
    return served


def _ban_manager_of_the_checks(app: FastAPI, config: SecurityConfig) -> object:
    state = get_state(config, None, app)
    assert state is not None and state.security_pipeline is not None
    limiter = next(
        c for c in state.security_pipeline.checks if isinstance(c, RateLimitCheck)
    )
    return limiter.ip_ban_manager


@pytest.fixture(autouse=True)
def collector_off() -> Iterator[None]:
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


async def test_a_startup_failure_releases_the_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail(self: SecurityMiddleware) -> None:
        raise RuntimeError("startup failed")

    monkeypatch.setattr(SecurityMiddleware, "initialize", fail)
    with pytest.raises(RuntimeError, match="startup failed"):
        async with guard_lifespan(_app(_config())):
            pytest.fail("the lifespan body must not run")
    assert _default_serves_a_new_app()


async def test_a_startup_failure_under_make_lifespan_releases_the_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail(self: SecurityMiddleware) -> None:
        raise RuntimeError("startup failed")

    monkeypatch.setattr(SecurityMiddleware, "initialize", fail)
    app = _app(_config())
    with pytest.raises(RuntimeError, match="startup failed"):
        async with make_lifespan()(app):
            pytest.fail("the lifespan body must not run")
    assert _default_serves_a_new_app()


async def test_a_cancelled_lifespan_releases_the_app() -> None:
    app = _app(_config())

    async def run() -> None:
        async with guard_lifespan(app):
            await asyncio.sleep(60)

    task = asyncio.create_task(run())
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert _default_serves_a_new_app()


async def test_a_close_that_raises_still_releases_and_the_error_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def failing_close(app: object) -> None:
        raise OSError("close failed")

    monkeypatch.setattr(lifespan_module, "_release_redis_hold", failing_close)
    with pytest.raises(OSError, match="close failed"):
        async with guard_lifespan(_app(_config())):
            pass
    assert _default_serves_a_new_app()


async def test_a_shared_config_is_released_by_the_last_running_app_to_stop() -> None:
    holder_config, shared = _config(), _config()
    holder = _app(holder_config)
    a, b = _app(shared), _app(shared)
    async with guard_lifespan(holder):
        async with guard_lifespan(a):
            async with guard_lifespan(b):
                await ip_ban_manager_for(shared).ban_ip(_IP, 60)
            own = ip_ban_manager_for(shared)
            assert own is not ipban_module.ip_ban_manager
            assert _ban_manager_of_the_checks(a, shared) is own
            assert await own.is_ip_banned(_IP)
        assert ip_ban_manager_for(shared) is ipban_module.ip_ban_manager
    assert _default_serves_a_new_app()


async def test_sequential_apps_on_one_config_do_not_share_state() -> None:
    """D-317: fastapi-guard calls release_app after the lifespan yield, so the second
    app starts with clean state on the default, not the first app's state."""
    config = _config()
    first = _app(config)
    async with guard_lifespan(first):
        await ip_ban_manager_for(config).ban_ip(_IP, 60)
        first_state = get_state(config, None, first)
        assert first_state is not None
    second = _app(config)
    async with guard_lifespan(second):
        manager = ip_ban_manager_for(config)
        assert manager is ipban_module.ip_ban_manager
        assert not await manager.is_ip_banned(_IP)
        second_state = get_state(config, None, second)
        assert second_state is not None
        assert second_state.security_pipeline is not first_state.security_pipeline


def test_lifespans_on_loops_in_two_threads_release_a_shared_config_once_at_the_end(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A behaviour pin, not red/green: the unlocked count race is timing dependent."""
    releases: list[object] = []
    closes: list[object] = []

    async def counting_close(app: object) -> None:
        closes.append(app)

    monkeypatch.setattr(lifespan_module, "_release_redis_hold", counting_close)
    real_release = lifespan_module._release_the_app
    monkeypatch.setattr(
        lifespan_module,
        "_release_the_app",
        lambda app: (releases.append(app), real_release(app))[1],
    )
    shared = _config()
    started = [threading.Event(), threading.Event()]
    stop = [threading.Event(), threading.Event()]

    def run(index: int) -> None:
        async def serve() -> None:
            async with guard_lifespan(_app(shared)):
                started[index].set()
                while not stop[index].is_set():
                    await asyncio.sleep(0.01)

        asyncio.run(serve())

    threads = [threading.Thread(target=run, args=(i,)) for i in range(2)]
    for thread in threads:
        thread.start()
    assert all(event.wait(10) for event in started)
    stop[0].set()
    threads[0].join(10)
    assert releases == [] and closes == []
    assert get_state(shared) is not None
    stop[1].set()
    threads[1].join(10)
    assert len(releases) == 1 and len(closes) == 1
