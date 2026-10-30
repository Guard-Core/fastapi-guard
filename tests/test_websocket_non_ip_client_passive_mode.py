from typing import Any

import pytest
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient
from guard_core.models import SecurityConfig
from starlette.websockets import WebSocketDisconnect

from guard import SecurityMiddleware, guard_websocket


def _app(passive_mode: bool, blocked: list[dict[str, object]]) -> FastAPI:
    def on_block(request: Any, payload: dict[str, object]) -> None:
        blocked.append(payload)

    config = SecurityConfig(
        enable_redis=False,
        enable_rate_limiting=True,
        passive_mode=passive_mode,
        fail_secure=True,
        trusted_proxies=[],
        on_block=on_block,
    )
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("hi")
        await websocket.close()

    return app


def test_a_non_ip_client_is_closed_1008_outside_passive_mode() -> None:
    # TestClient's default peer is the host name "testclient", not an address.
    blocked: list[dict[str, object]] = []
    with TestClient(_app(False, blocked)) as client:
        with pytest.raises(WebSocketDisconnect) as closed:
            with client.websocket_connect("/ws"):
                pass

    assert (closed.value.code, closed.value.reason) == (1008, "IP not allowed")
    assert blocked == []


def test_a_non_ip_client_in_passive_mode_is_admitted_and_logged() -> None:
    blocked: list[dict[str, object]] = []
    with TestClient(_app(True, blocked)) as client:
        with client.websocket_connect("/ws") as socket:
            assert socket.receive_text() == "hi"

    assert [payload["passive_mode"] for payload in blocked] == [True]
