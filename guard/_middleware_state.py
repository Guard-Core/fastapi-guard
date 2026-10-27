from __future__ import annotations

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


_STATE_REGISTRY: dict[tuple[int, int], MiddlewareState] = {}


def _state_key(config: object, decorator: object) -> tuple[int, int]:
    return (id(config), id(decorator))


def get_state(config: object, decorator: object = None) -> MiddlewareState | None:
    return _STATE_REGISTRY.get(_state_key(config, decorator))


def register_state(config: object, decorator: object, state: MiddlewareState) -> None:
    _STATE_REGISTRY[_state_key(config, decorator)] = state


def clear_state_registry() -> None:
    _STATE_REGISTRY.clear()
