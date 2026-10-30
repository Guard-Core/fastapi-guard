import itertools
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from guard_core.models import BehaviorRuleConfig, SecurityConfig
from guard_core.protocols import GuardResponse

from guard import PureASGISecurityMiddleware, SecurityMiddleware

_PATHS = ["/missing", "/ok", "/ok", "/ok", "/ok"]
_PEERS = itertools.count(10)


async def _modifier(response: GuardResponse) -> GuardResponse:
    response.headers["x-modified"] = "1"
    return response


def _observed(middleware: type[Any], **fields: Any) -> list[tuple[int, str | None]]:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        trusted_proxies=[],
        **fields,
    )
    app = FastAPI()
    app.add_middleware(middleware, config=config)

    @app.get("/ok")
    async def ok() -> dict[str, int]:
        return {"ok": 1}

    @app.get("/missing")
    async def missing() -> None:
        raise HTTPException(404)

    peer = (f"203.0.113.{next(_PEERS)}", 5000)
    with TestClient(app, client=peer) as client:
        responses = [client.get(path) for path in _PATHS]
    return [(r.status_code, r.headers.get("x-modified")) for r in responses]


def _both(**fields: Any) -> tuple[list[Any], list[Any]]:
    return (
        _observed(SecurityMiddleware, **fields),
        _observed(PureASGISecurityMiddleware, **fields),
    )


def test_a_custom_response_modifier_runs_on_every_response_of_both_middlewares() -> (
    None
):
    classic, pure = _both(custom_response_modifier=_modifier)

    assert classic == [(404, "1"), (200, "1"), (200, "1"), (200, "1"), (200, "1")]
    assert pure == classic


def test_a_usage_throttle_rule_answers_429_in_both_middlewares() -> None:
    classic, pure = _both(
        enable_rate_limiting=False,
        global_behavior_rules=[
            BehaviorRuleConfig(
                rule_type="usage", threshold=2, window=60, action="throttle"
            )
        ],
    )

    assert [status for status, _ in classic] == [404, 200, 429, 429, 429]
    assert pure == classic


@pytest.mark.parametrize("action", ["ban", "log"])
def test_a_return_pattern_rule_acts_the_same_in_both_middlewares(action: str) -> None:
    classic, pure = _both(
        global_behavior_rules=[
            BehaviorRuleConfig(
                rule_type="return_pattern",
                threshold=1,
                window=60,
                pattern="status:404",
                action=action,
                ban_duration=60,
            )
        ]
    )

    assert pure == classic


def test_a_request_refused_before_the_app_runs_is_refused_with_a_modifier() -> None:
    blocked = f"203.0.113.{next(_PEERS)}"
    statuses = []
    for middleware in (SecurityMiddleware, PureASGISecurityMiddleware):
        app = FastAPI()
        app.add_middleware(
            middleware,
            config=SecurityConfig(
                enable_redis=False,
                enable_penetration_detection=False,
                trusted_proxies=[],
                blacklist=[blocked],
                custom_response_modifier=_modifier,
            ),
        )

        @app.get("/ok")
        async def ok() -> dict[str, int]:
            return {"ok": 1}

        with TestClient(app, client=(blocked, 5000)) as client:
            statuses.append(client.get("/ok").status_code)

    assert statuses == [403, 403]
