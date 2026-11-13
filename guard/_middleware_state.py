from __future__ import annotations

import weakref
from dataclasses import dataclass

from guard_core.core.behavioral import BehavioralProcessor
from guard_core.core.bypass import BypassHandler
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.core.events import MetricsCollector, SecurityEventBus
from guard_core.core.initialization import HandlerInitializer
from guard_core.core.responses import ErrorResponseFactory
from guard_core.core.validation import RequestValidator
from guard_core.protocols import AgentHandlerProtocol


@dataclass
class MiddlewareState:
    security_pipeline: SecurityCheckPipeline | None
    composite_handler: AgentHandlerProtocol | None
    event_bus: SecurityEventBus
    metrics_collector: MetricsCollector
    response_factory: ErrorResponseFactory
    validator: RequestValidator
    bypass_handler: BypassHandler
    behavioral_processor: BehavioralProcessor
    handler_initializer: HandlerInitializer
    agent_handler: AgentHandlerProtocol | None


_STORE_ATTRIBUTE = "_guard_middleware_state_store"
_StateKey = tuple[int, int]


@dataclass
class _Entry:
    # Strong refs keep the key ids from being reused while the entry lives.
    config: object
    decorator: object
    state: MiddlewareState


_Store = dict[_StateKey, _Entry]


def _state_key(config: object, decorator: object) -> _StateKey:
    return (id(config), id(decorator))


def state_owner(request: object, fallback: object) -> object:
    scope = getattr(request, "scope", None)
    app = scope.get("app") if isinstance(scope, dict) else None
    return app if app is not None else fallback


class _StateRegistry:
    """Warm states live on the object that owns them (the ASGI app), so a state
    dies with its owner: the state reaches its owner through the pipeline's
    middleware, which a registry that held the state would keep alive forever.
    A call without an owner uses ``_ownerless``, which only an explicit clear drops.
    """

    def __init__(self) -> None:
        self._ownerless: _Store = {}
        self._owners: weakref.WeakSet[object] = weakref.WeakSet()

    def _store_of(self, owner: object) -> _Store | None:
        store: _Store | None = getattr(owner, _STORE_ATTRIBUTE, None)
        if store is not None:
            return store
        store = {}
        try:
            setattr(owner, _STORE_ATTRIBUTE, store)
            self._owners.add(owner)
        except (AttributeError, TypeError):
            return None
        return store

    def _live_stores(self) -> list[_Store]:
        stores = [getattr(o, _STORE_ATTRIBUTE, None) for o in list(self._owners)]
        return [store for store in stores if store is not None]

    def find(self, key: _StateKey, owner: object | None) -> _Entry | None:
        stores = [self._ownerless, *self._live_stores()]
        if owner is not None:
            own = getattr(owner, _STORE_ATTRIBUTE, None)
            if own is not None:
                stores.insert(0, own)
        for store in stores:
            entry = store.get(key)
            if entry is not None:
                return entry
        return None

    def put(self, key: _StateKey, entry: _Entry, owner: object | None) -> None:
        store = self._store_of(owner) if owner is not None else None
        (self._ownerless if store is None else store)[key] = entry

    def forget(self, key: _StateKey, owner: object | None) -> None:
        stores = [self._ownerless]
        own = getattr(owner, _STORE_ATTRIBUTE, None)
        if own is not None:
            stores.append(own)
        for store in stores:
            store.pop(key, None)

    def drop_config(self, config: object, owner: object) -> None:
        stores = [self._ownerless]
        own = getattr(owner, _STORE_ATTRIBUTE, None)
        if own is not None:
            stores.append(own)
        for store in stores:
            for key in [k for k, entry in store.items() if entry.config is config]:
                del store[key]

    def values(self) -> list[MiddlewareState]:
        stores = [self._ownerless, *self._live_stores()]
        return [entry.state for store in stores for entry in store.values()]

    def clear(self) -> None:
        self._ownerless.clear()
        for store in self._live_stores():
            store.clear()


_STATE_REGISTRY = _StateRegistry()


def get_state(
    config: object, decorator: object = None, owner: object | None = None
) -> MiddlewareState | None:
    key = _state_key(config, decorator)
    entry = _STATE_REGISTRY.find(key, owner)
    if entry is None:
        return None
    if owner is not None:
        _STATE_REGISTRY.put(key, entry, owner)
    return entry.state


def register_state(
    config: object,
    decorator: object,
    state: MiddlewareState,
    owner: object | None = None,
) -> None:
    _STATE_REGISTRY.put(
        _state_key(config, decorator), _Entry(config, decorator, state), owner
    )


def unregister_state(
    config: object, decorator: object, owner: object | None = None
) -> None:
    _STATE_REGISTRY.forget(_state_key(config, decorator), owner)


def drop_states_of(config: object, owner: object) -> None:
    _STATE_REGISTRY.drop_config(config, owner)


def clear_state_registry() -> None:
    _STATE_REGISTRY.clear()
