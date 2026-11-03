"""A real request to a routed endpoint makes the security event carry the
normalised ``route_template`` (LEDGER 6.549)."""

import httpx
import pytest
from fastapi import FastAPI
from guard_agent import GuardAgentHandler
from guard_agent.models import SecurityEvent

from guard import SecurityConfig
from guard.middleware import SecurityMiddleware


async def test_a_blocked_request_event_carries_the_route_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[SecurityEvent] = []

    async def record(self: GuardAgentHandler, event: SecurityEvent) -> None:
        sent.append(event)

    monkeypatch.setattr(GuardAgentHandler, "send_event", record)
    app = FastAPI()

    @app.get("/items/{item_id}")
    async def item(item_id: int) -> dict[str, int]:
        return {"id": item_id}

    app.add_middleware(
        SecurityMiddleware,
        config=SecurityConfig(
            enable_redis=False,
            enable_agent=True,
            agent_api_key="sk-test-0123456789",
            enable_rate_limiting=False,
            enable_ip_banning=False,
            blocked_user_agents=["badbot"],
        ),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/items/42", headers={"user-agent": "badbot"})

    assert response.status_code == 403
    assert [event.endpoint for event in sent] == ["/items/42"]
    assert [event.route_template for event in sent] == ["/items/{item_id}"]
