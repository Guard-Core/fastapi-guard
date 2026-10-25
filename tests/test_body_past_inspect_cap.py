from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi import FastAPI
from guard_core.core.events.middleware_events import SecurityEventBus
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from guard import SecurityConfig, SecurityDecorator
from guard.middleware import SecurityMiddleware

CAP = 1024
_PAYLOAD = b"1' UNION SELECT password FROM users--"
_PAST_THE_CAP_PAYLOAD = b"A" * (CAP + 5000) + _PAYLOAD
_ONE_BYTE_PAST = b"A" * (CAP + 1)
_AT_THE_CAP = b"A" * CAP
_HEADERS = {"Content-Type": "text/plain", "X-Forwarded-For": "203.0.113.50"}


@pytest.fixture
def captured_events(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    original = SecurityEventBus.send_middleware_event

    async def _capture(self: SecurityEventBus, *args: Any, **kwargs: Any) -> None:
        events.append(kwargs)
        await original(self, *args, **kwargs)

    monkeypatch.setattr(SecurityEventBus, "send_middleware_event", _capture)
    return events


def _chunked(payload: bytes, chunk_size: int = 512) -> AsyncIterator[bytes]:
    async def chunks() -> AsyncIterator[bytes]:
        for start in range(0, len(payload), chunk_size):
            yield payload[start : start + chunk_size]

    return chunks()


def _app(fail_secure: bool) -> FastAPI:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        detection_max_body_inspect_bytes=CAP,
        fail_secure=fail_secure,
        trusted_proxies=("127.0.0.1",),
        auto_ban_threshold=2,
    )
    app = FastAPI()
    decorator = SecurityDecorator(config)

    @app.post("/small")
    async def small() -> dict[str, str]:
        return {"ok": "small"}

    @decorator.max_request_size(len(_PAST_THE_CAP_PAYLOAD))
    @app.post("/large")
    async def large() -> dict[str, str]:
        return {"ok": "large"}

    app.add_middleware(SecurityMiddleware, config=config)
    app.state.guard_decorator = decorator
    return app


def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def _body_read_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in events if "Request body read failed" in e.get("reason", "")]


@pytest.mark.parametrize("chunked", [False, True])
@pytest.mark.parametrize("body", [_ONE_BYTE_PAST, _PAST_THE_CAP_PAYLOAD])
async def test_a_body_past_the_cap_is_refused_with_an_event_and_no_strike(
    body: bytes, chunked: bool, captured_events: list[dict[str, Any]]
) -> None:
    async with _client(_app(fail_secure=True)) as client:
        statuses = [
            (
                await client.post(
                    "/small",
                    content=_chunked(body) if chunked else body,
                    headers=_HEADERS,
                )
            ).status_code
            for _ in range(4)
        ]
        after = await client.post("/small", content=b"hello", headers=_HEADERS)

    assert statuses == [400, 400, 400, 400]
    assert after.status_code == 200
    assert len(_body_read_events(captured_events)) == 4
    assert {e["action_taken"] for e in _body_read_events(captured_events)} == {
        "request_blocked"
    }


@pytest.mark.parametrize("chunked", [False, True])
async def test_a_body_past_the_cap_passes_with_an_event_without_fail_secure(
    chunked: bool, captured_events: list[dict[str, Any]]
) -> None:
    async with _client(_app(fail_secure=False)) as client:
        response = await client.post(
            "/small",
            content=_chunked(_PAST_THE_CAP_PAYLOAD)
            if chunked
            else _PAST_THE_CAP_PAYLOAD,
            headers=_HEADERS,
        )

    assert response.status_code == 200
    assert [e["action_taken"] for e in _body_read_events(captured_events)] == [
        "logged_only"
    ]


@pytest.mark.parametrize("chunked", [False, True])
async def test_a_route_with_max_request_size_above_the_cap_is_scanned_in_full(
    chunked: bool,
) -> None:
    async with _client(_app(fail_secure=True)) as client:
        raised = await client.post(
            "/large",
            content=_chunked(_PAST_THE_CAP_PAYLOAD)
            if chunked
            else _PAST_THE_CAP_PAYLOAD,
            headers=_HEADERS,
        )
        sibling = await client.post(
            "/small",
            content=_chunked(_PAST_THE_CAP_PAYLOAD)
            if chunked
            else _PAST_THE_CAP_PAYLOAD,
            headers=_HEADERS,
        )

    assert raised.status_code == 400
    assert "Suspicious activity detected" in raised.text
    assert sibling.status_code == 400
    assert "Suspicious activity detected" not in sibling.text


@pytest.mark.parametrize("chunked", [False, True])
async def test_a_body_at_exactly_the_cap_is_scanned_in_full_and_unchanged(
    chunked: bool, captured_events: list[dict[str, Any]]
) -> None:
    hit = _AT_THE_CAP[: CAP - len(_PAYLOAD)] + _PAYLOAD
    async with _client(_app(fail_secure=True)) as client:
        clean = await client.post(
            "/small",
            content=_chunked(_AT_THE_CAP) if chunked else _AT_THE_CAP,
            headers=_HEADERS,
        )
        attack = await client.post(
            "/small", content=_chunked(hit) if chunked else hit, headers=_HEADERS
        )

    assert clean.status_code == 200
    assert attack.status_code == 400
    assert "Suspicious activity detected" in attack.text
    assert _body_read_events(captured_events) == []
