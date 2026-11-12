import importlib
import os
import sys
import weakref
from collections.abc import AsyncGenerator, Callable, Generator, Iterator
from pathlib import Path
from typing import Any, Concatenate, NoReturn, ParamSpec

import pytest
from fastapi import FastAPI
from guard_core import release_app
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers import cloud_handler as cloud_handler_module
from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.handlers.ipban_handler import reset_global_state
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.ratelimit_handler import rate_limit_handler
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from pytest import TempPathFactory

from guard._middleware_state import _STATE_REGISTRY, clear_state_registry
from guard.middleware import SecurityMiddleware
from tests import network_guard, thread_guard
from tests.redis_isolation import (
    REDIS_PREFIX,
    REDIS_URL,
    delete_every_key_under_the_suite_prefix,
    point_security_config_defaults_at_the_test_redis,
    refuse_connections_to_the_default_redis_port,
    refused_connections,
)

network_guard.install()
thread_guard.install()

point_security_config_defaults_at_the_test_redis()

# CI on fork PRs cannot read secrets, so fall back to a dummy token: the suite
# refuses all geo and cloud HTTP traffic (`_no_geo_or_cloud_network`) and
# IPInfoManager only requires a non-empty token at construction.
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN") or "test_token"

ADVANCED_APP_DIR = Path(__file__).resolve().parents[1] / "examples" / "advanced_app"


@pytest.fixture
def advanced_app_main(monkeypatch: pytest.MonkeyPatch) -> object:
    monkeypatch.setenv(
        "REDIS_URL", os.environ.get("REDIS_URL", "redis://localhost:6379")
    )
    monkeypatch.syspath_prepend(str(ADVANCED_APP_DIR))
    sys.modules.pop("app", None)
    sys.modules.pop("app.main", None)
    main = importlib.import_module("app.main")
    monkeypatch.setitem(
        importlib.import_module("app.routes.admin")._ADMIN_ADDED_LOOPBACK,
        "added",
        False,
    )
    return main


async def _close_redis_handler(redis_handler: RedisManager) -> None:
    try:
        await redis_handler.close()
    except RuntimeError as exc:
        if "Event loop is closed" not in str(exc):
            raise


@pytest.fixture(autouse=True)
def _no_geo_or_cloud_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """The suite never reaches ipinfo.io or a cloud provider: a download fails at
    once, as it does without a network, instead of opening a socket that outlives
    the test."""

    async def refuse_database(self: IPInfoManager) -> None:
        raise ConnectionError("the test suite has no network")

    async def refuse_ranges(provider: str) -> NoReturn:
        raise ConnectionError("the test suite has no network")

    monkeypatch.setattr(IPInfoManager, "_fetch_and_store_database", refuse_database)
    monkeypatch.setattr(cloud_handler_module, "_fetch_provider_ranges", refuse_ranges)


@pytest.fixture(autouse=True)
async def _clear_middleware_state_registry() -> AsyncGenerator[None, None]:
    clear_state_registry()
    yield
    for state in _STATE_REGISTRY.values():
        redis_handler = state.handler_initializer.redis_handler
        if isinstance(redis_handler, RedisManager):
            await _close_redis_handler(redis_handler)
    clear_state_registry()


@pytest.fixture(scope="session", autouse=True)
def _refuse_the_default_redis_port() -> Generator[None, None, None]:
    with pytest.MonkeyPatch.context() as monkeypatch:
        refuse_connections_to_the_default_redis_port(monkeypatch)
        yield


@pytest.fixture(autouse=True)
def refused_redis_connections() -> Generator[list[tuple[Any, ...]], None, None]:
    refused_connections.clear()
    yield refused_connections
    attempts = list(refused_connections)
    refused_connections.clear()
    assert not attempts, f"the test connected to port 6379: {attempts}"


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    terminalreporter.write_line(
        f"redis isolation: REDIS_URL={REDIS_URL} REDIS_PREFIX={REDIS_PREFIX}"
    )


@pytest.fixture(scope="session", autouse=True)
def _engine_default_redis_url_follows_redis_url() -> None:
    # A SecurityConfig built without redis_url falls back to localhost:6379, which
    # is not where Redis lives inside the compose network.
    SecurityConfig.model_fields["redis_url"].default = REDIS_URL
    SecurityConfig.model_rebuild(force=True)


_P = ParamSpec("_P")


def _recording_the_config_it_binds(
    original: Callable[Concatenate[HandlerInitializer, _P], None],
    bound: list[weakref.ref[SecurityConfig]],
) -> Callable[Concatenate[HandlerInitializer, _P], None]:
    def initializer(
        self: HandlerInitializer, *args: _P.args, **kwargs: _P.kwargs
    ) -> None:
        original(self, *args, **kwargs)
        bound.append(weakref.ref(self.config))

    return initializer


@pytest.fixture(autouse=True)
def _release_every_app_between_tests(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """HandlerInitializer binds an app's config to the engine's managers; a test
    that built an app and never ran its lifespan leaves the config bound until
    the collector frees it, so the next test could get the default or its own
    managers depending on when the collector ran (D-317)."""
    bound: list[weakref.ref[SecurityConfig]] = []
    monkeypatch.setattr(
        HandlerInitializer,
        "__init__",
        _recording_the_config_it_binds(HandlerInitializer.__init__, bound),
    )
    yield
    for reference in bound:
        config = reference()
        if config is not None:
            release_app(config)


@pytest.fixture(autouse=True)
async def reset_state() -> AsyncGenerator[None, None]:
    # Reset IPBanManager
    await reset_global_state()

    # Reset SusPatternsManager
    original_patterns = sus_patterns_handler.patterns.copy()

    # Reset CloudManager
    cloud_instance = cloud_handler._instance
    if cloud_instance:
        cloud_instance.ip_ranges = {"AWS": set(), "GCP": set(), "Azure": set()}
        cloud_instance.redis_handler = None

    # Reset IPInfoManager
    if IPInfoManager._instance:
        if IPInfoManager._instance.reader:
            IPInfoManager._instance.reader.close()
        IPInfoManager._instance = None

    yield
    sus_patterns_handler.patterns = original_patterns.copy()


@pytest.fixture
def security_config() -> SecurityConfig:
    """
    Fixture to create a SecurityConfig object for testing.

    Returns:
        SecurityConfig: A configured SecurityConfig object.
    """
    return SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN, None),
        enable_redis=False,
        enable_penetration_detection=False,
        whitelist=("127.0.0.1", "203.0.113.5"),
        blacklist=("192.168.1.1",),
        blocked_countries=frozenset({"CN"}),
        blocked_user_agents=[r"badbot"],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_log_file="test_log.log",
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600,
    )


@pytest.fixture
async def security_middleware() -> AsyncGenerator[SecurityMiddleware, None]:
    config = SecurityConfig(
        enable_penetration_detection=False,
        whitelist=(),
        blacklist=(),
        auto_ban_threshold=10,
        auto_ban_duration=300,
    )
    app = FastAPI()
    middleware = SecurityMiddleware(app=app, config=config)
    yield middleware
    await middleware.reset()


@pytest.fixture(scope="session")
def ipinfo_db_path(tmp_path_factory: TempPathFactory) -> Path:
    """Shared temporary path for IPInfo database"""
    return tmp_path_factory.mktemp("ipinfo_data") / "country_asn.mmdb"


@pytest.fixture
def security_config_redis(ipinfo_db_path: Path) -> SecurityConfig:
    """SecurityConfig with Redis enabled"""
    return SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN, ipinfo_db_path),
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX,
        enable_penetration_detection=False,
        whitelist=("127.0.0.1",),
        blacklist=("192.168.1.1",),
        blocked_countries=frozenset({"CN"}),
        blocked_user_agents=[r"badbot"],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_log_file="test_log.log",
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600,
    )


@pytest.fixture(autouse=True)
def redis_cleanup() -> None:
    """Delete only the keys under this suite's own prefix before each test"""
    delete_every_key_under_the_suite_prefix()


@pytest.fixture(autouse=True, scope="session")
def redis_cleanup_at_session_end() -> Generator[None, None, None]:
    yield
    delete_every_key_under_the_suite_prefix()


@pytest.fixture(autouse=True)
async def reset_rate_limiter() -> AsyncGenerator[None, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX,
        enable_redis=True,
    )
    rate_limit = rate_limit_handler(config)
    previous_redis = rate_limit.redis_handler

    await rate_limit.reset()
    if isinstance(previous_redis, RedisManager):
        await previous_redis.close()

    fresh_redis = RedisManager(config)
    await fresh_redis.initialize()
    rate_limit.redis_handler = fresh_redis
    rate_limit.rate_limit_script_sha = None

    yield

    await _close_redis_handler(fresh_redis)
    rate_limit.redis_handler = None


@pytest.fixture
def clean_rate_limiter() -> None:
    """Reset rate limiter singleton for tests that need a completely clean state"""
    from guard_core.handlers.ratelimit_handler import _managers, _managers_lock

    with _managers_lock:
        _managers.clear()


@pytest.fixture(autouse=True)
def _no_outbound_network() -> Iterator[None]:
    network_guard.reset()
    yield
    violations = network_guard.drain()
    assert not violations, "test reached the network:\n" + "\n".join(violations)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    thread_guard.stop_the_shared_regex_pools()
    leaked = thread_guard.leaked_threads()
    if leaked:
        sys.stderr.write(f"\nthreads the tests left running: {leaked}\n")
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
