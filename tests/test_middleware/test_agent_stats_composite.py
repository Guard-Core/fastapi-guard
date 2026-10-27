import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from guard_core.core.events.composite_handler import CompositeAgentHandler
from guard_core.models import SecurityConfig

from guard.middleware import SecurityMiddleware


class _StatsAgentStub:
    def __init__(self) -> None:
        self.stats: dict[str, object] = {"buffer_stats": {"events_dropped": 3}}

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def flush_buffer(self) -> None: ...

    async def send_event(self, event: object) -> None: ...

    async def send_metric(self, metric: object) -> None: ...

    async def initialize_redis(self, redis_handler: object) -> None: ...

    async def get_dynamic_rules(self) -> None:
        return None

    async def get_status(self) -> None:
        return None

    async def health_check(self) -> bool:
        return True

    def get_stats(self) -> dict[str, object]:
        return self.stats


async def test_agent_stats_answers_after_the_composite_handler_is_swapped_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = _StatsAgentStub()
    monkeypatch.setitem(
        sys.modules, "guard_agent", SimpleNamespace(GuardAgentHandler=lambda _cfg: stub)
    )
    config = SecurityConfig(enable_agent=True, agent_api_key="x", enable_redis=False)
    with patch.object(SecurityConfig, "to_agent_config", return_value=object()):
        middleware = SecurityMiddleware(FastAPI(), config=config)

    await middleware.initialize()

    assert isinstance(middleware.agent_handler, CompositeAgentHandler)
    stats = middleware.agent_stats
    assert stats["enabled"] is True
    assert stats["buffer_stats"] == {"events_dropped": 3}
