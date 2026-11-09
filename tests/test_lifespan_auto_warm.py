"""LEDGER 6.697 / D-290 item 2: both middleware classes warm the engine on the ASGI
lifespan startup, with no guard_lifespan wiring and no opt-out field."""

import asyncio
import socket
import time
import uuid
from collections.abc import AsyncIterator, MutableMapping
from contextlib import asynccontextmanager, suppress
from typing import Any

import pytest
from fastapi import FastAPI
from guard_core.exceptions import GuardRedisError
from guard_core.handlers._ipban_bans import _VERSION_PAIR
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from httpx import ASGITransport, AsyncClient

import guard.lifespan as lifespan_module
from guard._middleware_state import get_state
from guard.asgi import PureASGISecurityMiddleware
from guard.lifespan import guard_startup, make_lifespan
from guard.middleware import SecurityMiddleware
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL
from tests.test_redis_cold_start_recovery import RedisForwarder, keys_under

CLASSES = pytest.mark.parametrize(
    "middleware_class",
    [SecurityMiddleware, PureASGISecurityMiddleware],
    ids=["classic", "pure"],
)
CLIENT = ("203.0.113.9", 4321)


def _config(url: str = REDIS_URL, **overrides: Any) -> SecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": True,
        "redis_url": url,
        "redis_prefix": f"{REDIS_PREFIX}wp490:{uuid.uuid4().hex[:8]}:",
        "enable_agent": False,
        "enable_penetration_detection": False,
        "custom_log_file": "test_log.log",
    }
    settings.update(overrides)
    return SecurityConfig(**settings)


def _app(middleware_class: Any, config: SecurityConfig, **kwargs: Any) -> FastAPI:
    app = FastAPI(**kwargs)
    app.add_middleware(middleware_class, config=config)

    @app.get("/ping")
    async def ping() -> dict[str, bool]:
        return {"ok": True}

    return app


class Lifespan:
    def __init__(self, app: FastAPI) -> None:
        self.app = app
        self.sent: list[MutableMapping[str, Any]] = []
        self.task: asyncio.Task[None] | None = None
        self._inbox: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._outbox: asyncio.Queue[MutableMapping[str, Any]] = asyncio.Queue()

    async def _send(self, message: MutableMapping[str, Any]) -> None:
        self.sent.append(message)
        await self._outbox.put(message)

    async def start(self) -> str:
        scope = {"type": "lifespan", "asgi": {"version": "3.0"}, "state": {}}
        self.task = asyncio.create_task(self.app(scope, self._inbox.get, self._send))
        await self._inbox.put({"type": "lifespan.startup"})
        waiter = asyncio.create_task(self._outbox.get())
        await asyncio.wait({waiter, self.task}, return_when=asyncio.FIRST_COMPLETED)
        if not waiter.done():
            waiter.cancel()
            return "task ended without a startup message"
        return str(waiter.result()["type"])

    async def stop(self) -> None:
        assert self.task is not None
        if not self.task.done():
            await self._inbox.put({"type": "lifespan.shutdown"})
            await asyncio.wait_for(self.task, 5)
        with suppress(Exception):
            await self.task


@asynccontextmanager
async def started(app: FastAPI) -> AsyncIterator[Lifespan]:
    lifespan = Lifespan(app)
    assert await lifespan.start() == "lifespan.startup.complete"
    try:
        yield lifespan
    finally:
        await lifespan.stop()


def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app, client=CLIENT), base_url="http://t")


def _redis_handler_of(config: SecurityConfig) -> Any:
    from guard_core._utils.config_registry import REDIS_HANDLERS

    return REDIS_HANDLERS.lookup(config)


async def _close_handler_of(config: SecurityConfig) -> None:
    handler = _redis_handler_of(config)
    if isinstance(handler, RedisManager):
        await handler.close()


async def _ban_in_redis(config: SecurityConfig, ip: str) -> None:
    seeder = RedisManager(SecurityConfig(**config.model_dump(include=_SEED_FIELDS)))
    await seeder.initialize()
    try:
        await seeder.write_ban_extending_only(
            "banned_ips", ip, str(time.time() + 300), 300, version=_VERSION_PAIR
        )
    finally:
        await seeder.close()


_SEED_FIELDS = {"enable_redis", "redis_url", "redis_prefix", "enable_agent"}


def _closed_port_url() -> str:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return f"redis://127.0.0.1:{port}/0"


@asynccontextmanager
async def _hung_redis() -> AsyncIterator[str]:
    release = asyncio.Event()

    async def never_answer(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await release.wait()
        writer.close()

    server = await asyncio.start_server(never_answer, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"redis://127.0.0.1:{port}/0"
    finally:
        release.set()
        server.close()
        await server.wait_closed()


@CLASSES
async def test_redis_is_bound_before_the_first_request(
    middleware_class: type,
) -> None:
    config = _config()
    app = _app(middleware_class, config)
    try:
        async with started(app):
            handler = _redis_handler_of(config)
            assert isinstance(handler, RedisManager)
            assert handler._redis is not None
    finally:
        await _close_handler_of(config)


@CLASSES
async def test_an_ip_banned_in_redis_before_start_gets_403_on_its_first_request(
    middleware_class: type,
) -> None:
    config = _config()
    await _ban_in_redis(config, CLIENT[0])
    app = _app(middleware_class, config)
    try:
        async with started(app):
            assert _redis_handler_of(config)._redis is not None
            async with _client(app) as client:
                assert (await client.get("/ping")).status_code == 403
    finally:
        await _close_handler_of(config)


@CLASSES
async def test_redis_refused_startup_completes_and_the_first_request_is_as_before(
    middleware_class: type,
) -> None:
    config = _config(_closed_port_url(), redis_fail_open=True)
    app = _app(middleware_class, config)
    async with started(app):
        async with _client(app) as client:
            assert (await client.get("/ping")).status_code == 200


@CLASSES
async def test_redis_refused_startup_completes_when_failing_closed(
    middleware_class: type,
) -> None:
    config = _config(_closed_port_url(), redis_fail_open=False)
    app = _app(middleware_class, config)
    async with started(app):
        async with _client(app) as client:
            assert (await client.get("/ping")).status_code == 503


@CLASSES
async def test_redis_hung_startup_completes_and_no_later_request_is_slow(
    middleware_class: type,
) -> None:
    async with _hung_redis() as url:
        config = _config(url, redis_fail_open=True)
        app = _app(middleware_class, config)
        async with started(app):
            async with _client(app) as client:
                for _ in range(20):
                    begun = time.monotonic()
                    assert (await client.get("/ping")).status_code == 200
                    assert time.monotonic() - begun < 0.5


@CLASSES
async def test_a_misconfiguration_stops_the_boot(middleware_class: type) -> None:
    config = _config(
        enable_redis=False,
        auto_ban_threshold=1_000_000,
        fail_on_misconfiguration=True,
    )
    lifespan = Lifespan(_app(middleware_class, config))

    assert await lifespan.start() == "lifespan.startup.failed"
    await lifespan.stop()


@CLASSES
async def test_a_misconfiguration_boots_when_the_flag_is_off(
    middleware_class: type,
) -> None:
    config = _config(
        enable_redis=False,
        auto_ban_threshold=1_000_000,
        fail_on_misconfiguration=False,
    )
    async with started(_app(middleware_class, config)):
        pass


def _count_initializations(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = []
    original = SecurityMiddleware.initialize

    async def counting(self: SecurityMiddleware) -> None:
        calls.append(1)
        await original(self)

    monkeypatch.setattr(SecurityMiddleware, "initialize", counting)
    return calls


async def test_make_lifespan_and_the_middleware_warm_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _count_initializations(monkeypatch)
    config = _config()
    app = _app(SecurityMiddleware, config, lifespan=make_lifespan())
    try:
        async with started(app):
            async with _client(app) as client:
                assert (await client.get("/ping")).status_code == 200
    finally:
        await _close_handler_of(config)

    assert len(calls) == 1


async def test_guard_startup_in_the_app_lifespan_and_the_middleware_warm_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _count_initializations(monkeypatch)
    config = _config()

    @asynccontextmanager
    async def own(app: FastAPI) -> AsyncIterator[None]:
        await guard_startup(app)
        yield

    app = _app(SecurityMiddleware, config, lifespan=own)
    try:
        async with started(app):
            assert get_state(config, None, app) is not None
    finally:
        await _close_handler_of(config)

    assert len(calls) == 1


@CLASSES
async def test_two_lifespan_startups_warm_once(
    middleware_class: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _count_initializations(monkeypatch)
    config = _config()
    app = _app(middleware_class, config)
    try:
        async with started(app):
            pass
        async with started(app):
            pass
    finally:
        await _close_handler_of(config)

    assert len(calls) == 1


@CLASSES
async def test_the_warm_runs_after_the_apps_own_startup_and_before_complete(
    middleware_class: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    order: list[str] = []
    original = lifespan_module._warm_middleware_or_adopt

    async def recording(middleware: Any, app: object) -> None:
        order.append("warm")
        await original(middleware, app)

    monkeypatch.setattr(lifespan_module, "_warm_middleware_or_adopt", recording)

    @asynccontextmanager
    async def own(app: FastAPI) -> AsyncIterator[None]:
        order.append("app startup")
        yield

    config = _config(enable_redis=False)
    lifespan = Lifespan(_app(middleware_class, config, lifespan=own))
    assert await lifespan.start() == "lifespan.startup.complete"
    order.append("complete forwarded")
    await lifespan.stop()

    assert order == ["app startup", "warm", "complete forwarded"]


@CLASSES
async def test_without_lifespan_messages_the_first_request_initializes(
    middleware_class: type,
) -> None:
    config = _config()
    app = _app(middleware_class, config)
    try:
        assert _redis_handler_of(config) is None
        async with _client(app) as client:
            assert (await client.get("/ping")).status_code == 200
        assert _redis_handler_of(config)._redis is not None
    finally:
        await _close_handler_of(config)


async def test_a_redis_error_never_fails_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def refuse(self: SecurityMiddleware) -> None:
        raise GuardRedisError(503, "down")

    monkeypatch.setattr(SecurityMiddleware, "initialize", refuse)
    app = _app(SecurityMiddleware, _config(enable_redis=False))
    async with started(app):
        pass


@CLASSES
async def test_fail_open_boot_with_redis_down_uses_redis_once_it_is_back(
    middleware_class: type,
) -> None:
    forwarder = RedisForwarder()
    config = _config(forwarder.url, redis_fail_open=True)
    app = _app(middleware_class, config)
    try:
        async with started(app):
            async with _client(app) as client:
                assert (await client.get("/ping")).status_code == 200
                assert keys_under(config.redis_prefix) == 0
                forwarder.on()
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    assert (await client.get("/ping")).status_code == 200
                    if keys_under(config.redis_prefix) > 0:
                        break
                    await asyncio.sleep(0.1)
                assert keys_under(config.redis_prefix) > 0
    finally:
        forwarder.off()
        await _close_handler_of(config)


def _open_the_reconnect_window(config: SecurityConfig) -> None:
    _redis_handler_of(config)._reconnect_gate()._not_before = 0.0


@asynccontextmanager
async def _blocked_background_attempt() -> AsyncIterator[asyncio.Event]:
    release = asyncio.Event()
    entered = asyncio.Event()

    async def blocked(self: RedisManager, url: str) -> None:
        entered.set()
        await release.wait()

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(RedisManager, "_attempt_in_background", blocked, raising=False)
        try:
            yield entered
        finally:
            release.set()


@CLASSES
async def test_a_second_warm_after_a_failed_cold_start_does_not_wait_for_the_attempt(
    middleware_class: type,
) -> None:
    config = _config(_closed_port_url(), redis_fail_open=False)
    app = _app(middleware_class, config)
    async with started(app):
        pass
    _open_the_reconnect_window(config)
    async with _blocked_background_attempt() as entered:
        async with started(app):
            await asyncio.wait_for(entered.wait(), 1)


@CLASSES
async def test_a_degraded_shared_manager_does_not_hold_startup(
    middleware_class: type,
) -> None:
    first = _config(_closed_port_url(), redis_fail_open=False)
    async with started(_app(middleware_class, first)):
        pass
    _open_the_reconnect_window(first)
    async with _blocked_background_attempt() as entered:
        async with started(_app(middleware_class, first)):
            await asyncio.wait_for(entered.wait(), 1)


async def _fail_closed_requests_after_a_failed_warm(
    middleware_class: type, monkeypatch: pytest.MonkeyPatch
) -> tuple[int, int]:
    calls = _count_initializations(monkeypatch)
    config = _config(_closed_port_url(), redis_fail_open=False)
    app = _app(middleware_class, config)
    async with started(app):
        after_startup = len(calls)
        async with _client(app) as client:
            for _ in range(5):
                assert (await client.get("/ping")).status_code == 503
    return after_startup, len(calls)


@CLASSES
async def test_fail_closed_boot_with_redis_down_answers_503(
    middleware_class: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    after_startup, _ = await _fail_closed_requests_after_a_failed_warm(
        middleware_class, monkeypatch
    )

    assert after_startup == 1


@CLASSES
async def test_fail_closed_boot_with_redis_down_builds_the_pipeline_once(
    middleware_class: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    builds: list[int] = []
    original = SecurityMiddleware._build_security_pipeline

    def counting(self: SecurityMiddleware) -> None:
        builds.append(1)
        original(self)

    monkeypatch.setattr(SecurityMiddleware, "_build_security_pipeline", counting)
    await _fail_closed_requests_after_a_failed_warm(middleware_class, monkeypatch)

    assert len(builds) == 1
