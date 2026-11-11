from __future__ import annotations

import gc
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core import release_app
from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.models import SecurityConfig

from guard._middleware_state import get_state
from guard.lifespan import guard_lifespan, make_lifespan
from guard.middleware import SecurityMiddleware
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL

_APPS = 200


def _config(prefix: str | None = None) -> SecurityConfig:
    if prefix is None:
        return SecurityConfig(enable_redis=False)
    return SecurityConfig(enable_redis=True, redis_url=REDIS_URL, redis_prefix=prefix)


def _app(config: SecurityConfig, lifespan: bool = True) -> FastAPI:
    app = FastAPI(lifespan=guard_lifespan) if lifespan else FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    def root() -> dict[str, bool]:
        return {"ok": True}

    return app


def _serve_once(app: FastAPI) -> None:
    with TestClient(app) as client:
        client.get("/")


def _default_ban_manager_serves_a_new_app() -> bool:
    new_app_config = _config()
    return ip_ban_manager_for(new_app_config, bind=True) is ipban_module.ip_ban_manager


def _default_ban_manager_serves_a_new_app_on(prefix: str) -> bool:
    return ip_ban_manager_for(_config(prefix), bind=True) is ipban_module.ip_ban_manager


@pytest.fixture
def collector_off() -> Iterator[None]:
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


def _live_security_configs() -> int:
    gc.collect()
    return sum(1 for o in gc.get_objects() if isinstance(o, SecurityConfig))


@pytest.mark.usefixtures("collector_off")
def test_a_new_app_resolves_the_default_after_the_lifespan_released_the_first() -> None:
    first = _app(_config())
    _serve_once(first)
    assert _default_ban_manager_serves_a_new_app()


@pytest.mark.usefixtures("collector_off")
def test_make_lifespan_releases_the_app_the_same_way() -> None:
    app = FastAPI(lifespan=make_lifespan())
    app.add_middleware(SecurityMiddleware, config=_config())
    _serve_once(app)
    assert _default_ban_manager_serves_a_new_app()


@pytest.mark.usefixtures("collector_off")
def test_a_testclient_used_without_with_never_runs_the_lifespan_and_keeps_the_app() -> (
    None
):
    first_config = _config()
    first = _app(first_config)
    TestClient(first).get("/")
    assert get_state(first_config) is not None
    assert not _default_ban_manager_serves_a_new_app()


def test_the_released_apps_state_is_dropped_from_the_registry() -> None:
    config = _config()
    app = _app(config)
    with TestClient(app) as client:
        client.get("/")
        assert get_state(config, None, app) is not None
    assert get_state(config, None, app) is None


def test_two_hundred_released_apps_leave_no_security_config() -> None:
    before = _live_security_configs()
    for _ in range(_APPS):
        _serve_once(_app(_config()))
    assert _live_security_configs() - before == 0


def test_apps_that_share_a_prefix_keep_the_default_until_the_last_one_is_released() -> (
    None
):
    first_config = _config(REDIS_PREFIX)
    second_config = _config(REDIS_PREFIX)
    first, second = _app(first_config), _app(second_config)
    with TestClient(second) as second_client:
        with TestClient(first) as first_client:
            first_client.get("/")
            second_client.get("/")
        assert ip_ban_manager_for(second_config) is ipban_module.ip_ban_manager
        assert not _default_ban_manager_serves_a_new_app_on(f"{REDIS_PREFIX}other:")
    assert _default_ban_manager_serves_a_new_app_on(f"{REDIS_PREFIX}other:")


async def test_the_config_is_bound_before_the_pipeline_is_built() -> None:
    _first = SecurityMiddleware(FastAPI(), config=_config())
    second_config = _config()
    second = SecurityMiddleware(FastAPI(), config=second_config)
    await second.initialize()
    assert second.security_pipeline is not None
    limiters = [
        check
        for check in second.security_pipeline.checks
        if isinstance(check, RateLimitCheck)
    ]
    own = ip_ban_manager_for(second_config)
    assert own is not ipban_module.ip_ban_manager
    assert limiters
    assert all(limiter.ip_ban_manager is own for limiter in limiters)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "needs the release epoch of WP616 round 4 (D-317 amendment 2); "
        "engine c12be493 does not rebuild a pipeline after a release"
    ),
)
def test_a_request_after_a_release_rebuilds_the_pipeline_of_the_reused_app() -> None:
    config = _config()
    app = _app(config, lifespan=False)
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        state = get_state(config, None, app)
        assert state is not None and state.security_pipeline is not None
        pipeline = state.security_pipeline
        checks_before = pipeline.checks
        release_app(config)
        assert client.get("/").status_code == 200
    assert pipeline.checks is not checks_before
