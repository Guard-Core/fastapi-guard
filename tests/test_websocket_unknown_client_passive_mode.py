from typing import Any

from fastapi import Depends, FastAPI, WebSocket
from guard_core.models import SecurityConfig
from starlette.exceptions import WebSocketException
from starlette.types import Message, Scope

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


async def _handshake(app: FastAPI) -> list[Message]:
    """Drive a handshake whose server reports no peer address at all."""
    scope: Scope = {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "scheme": "ws",
        "path": "/ws",
        "raw_path": b"/ws",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"t")],
        "subprotocols": [],
        "server": ("t", 80),
        "client": None,
        "app": app,
    }
    inbox = [{"type": "websocket.connect"}, {"type": "websocket.disconnect"}]
    sent: list[Message] = []

    async def receive() -> Message:
        return inbox.pop(0) if inbox else {"type": "websocket.disconnect"}

    async def send(message: Message) -> None:
        sent.append(message)

    try:
        await app(scope, receive, send)
    except WebSocketException:
        pass
    return sent


async def test_a_client_with_no_address_is_closed_1008_outside_passive_mode() -> None:
    blocked: list[dict[str, object]] = []

    sent = await _handshake(_app(False, blocked))

    assert [m["type"] for m in sent] == ["websocket.close"]
    assert sent[0]["code"] == 1008
    assert blocked == []


async def test_a_client_with_no_address_in_passive_mode_is_logged_and_admitted() -> (
    None
):
    blocked: list[dict[str, object]] = []

    sent = await _handshake(_app(True, blocked))

    assert sent[0]["type"] == "websocket.accept"
    assert [payload["passive_mode"] for payload in blocked] == [True]
