"""The adapters answer a refusal from their own usage-rules call.

An engine older than the one that evaluates usage rules inside the pipeline
(guard-core 4.4.x) leaves the refusal to this call, so these tests patch only
the call the adapters make (`process_usage_rules`) and leave the pipeline's own
evaluation (`evaluate_usage_rules`) alone.
"""

import itertools
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from guard_core.core.behavioral.processor import BehavioralProcessor
from guard_core.models import BehaviorRuleConfig
from httpx import ASGITransport, AsyncClient

from guard import PureASGISecurityMiddleware, SecurityConfig
from guard.adapters import StarletteGuardResponse
from guard.middleware import SecurityMiddleware

_IP = itertools.count(1)
_ORIGIN = "http://good.origin"


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_cors=True,
        cors_allow_origins=[_ORIGIN],
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="usage", threshold=100, window=60, action="throttle"
            ),
        ),
    )


def _app() -> FastAPI:
    app = FastAPI()

    @app.get("/ping")
    async def ping() -> dict[str, bool]:
        return {"ok": True}

    return app


@pytest.mark.parametrize("variant", ["classic", "pure_asgi"])
async def test_usage_call_refusal_is_answered_with_cors_headers(
    variant: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    refusal = StarletteGuardResponse(
        JSONResponse({"detail": "slow down"}, status_code=429)
    )
    usage = AsyncMock(return_value=refusal)
    monkeypatch.setattr(BehavioralProcessor, "process_usage_rules", usage)
    app = _app()
    if variant == "classic":
        app.add_middleware(SecurityMiddleware, config=_config())
        served = app
    else:
        served = PureASGISecurityMiddleware(app, config=_config())
    client_ip = f"198.51.100.{next(_IP)}"

    async with AsyncClient(
        transport=ASGITransport(app=served, client=(client_ip, 50000)),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/ping", headers={"Origin": _ORIGIN})

    assert response.status_code == 429
    assert response.json() == {"detail": "slow down"}
    assert response.headers["access-control-allow-origin"] == _ORIGIN
    usage.assert_awaited_once()
