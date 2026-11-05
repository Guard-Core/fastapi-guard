from __future__ import annotations

import gc
import weakref

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.models import SecurityConfig

from guard._middleware_state import get_state, register_state
from guard.lifespan import guard_lifespan
from guard.middleware import SecurityMiddleware
from guard.websocket import _resolve_shared_suspicious_counts

# guard-core keeps one config in SusPatternsManager._config and one in the
# module-level ip_ban_manager (the last config each was handed), so a fixed two
# configs may outlive every app. Anything above that is a leaked app.
ENGINE_SINGLETON_CONFIGS = 2


def _app(config: SecurityConfig, lifespan: bool = False) -> FastAPI:
    app = FastAPI(lifespan=guard_lifespan) if lifespan else FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    def root() -> dict[str, bool]:
        return {"ok": True}

    return app


def _request_once(app: FastAPI) -> None:
    with TestClient(app) as client:
        client.get("/")


def _live_security_configs() -> int:
    gc.collect()
    return sum(1 for o in gc.get_objects() if isinstance(o, SecurityConfig))


@pytest.mark.parametrize("apps", [10, 50])
def test_dropped_apps_do_not_keep_their_security_config(apps: int) -> None:
    before = _live_security_configs()
    for _ in range(apps):
        _request_once(_app(SecurityConfig(enable_redis=False)))
    assert _live_security_configs() - before <= ENGINE_SINGLETON_CONFIGS


def test_state_is_reused_by_a_rebuilt_middleware_and_the_websocket_path() -> None:
    config = SecurityConfig(enable_redis=False)
    app = _app(config, lifespan=True)
    with TestClient(app) as client:
        client.get("/")
        warm = get_state(config)
        assert warm is not None
        app.middleware_stack = app.build_middleware_stack()
        client.get("/")
        assert get_state(config) is warm
        assert _resolve_shared_suspicious_counts(app, config) is not None


def test_a_new_app_never_gets_a_dead_apps_state() -> None:
    dead_config = SecurityConfig(enable_redis=False)
    app = _app(dead_config)
    _request_once(app)
    dead_state = weakref.ref(get_state(dead_config))
    dead_config_id = id(dead_config)
    del app, dead_config
    # The two engine singletons still hold the last config; hand them another.
    _request_once(_app(SecurityConfig(enable_redis=False)))
    gc.collect()
    assert dead_state() is None
    # Allocate configs until one lands on the freed id (best effort), then check
    # that none of them finds a state it never registered.
    kept = []
    for _ in range(500):
        fresh = SecurityConfig(enable_redis=False)
        kept.append(fresh)
        assert get_state(fresh) is None
        if id(fresh) == dead_config_id:
            break
    new_app = _app(kept[-1])
    _request_once(new_app)
    assert get_state(kept[-1]) is not None


class _SlottedOwner:
    __slots__ = ("__weakref__",)


def test_an_owner_without_room_for_the_store_uses_the_ownerless_registry() -> None:
    config = SecurityConfig(enable_redis=False)
    app = _app(config)
    _request_once(app)
    state = get_state(config)
    assert state is not None
    other = SecurityConfig(enable_redis=False)
    register_state(other, None, state, _SlottedOwner())
    assert get_state(other) is state
