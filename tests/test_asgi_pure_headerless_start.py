from guard_core.models import SecurityConfig
from starlette.types import Message, Receive, Scope, Send

from guard import PureASGISecurityMiddleware


async def _status_only_app(scope: Scope, receive: Receive, send: Send) -> None:
    await send({"type": "http.response.start", "status": 204})
    await send({"type": "http.response.body", "body": b""})


async def test_a_response_start_without_headers_is_served_with_guard_headers() -> None:
    app = PureASGISecurityMiddleware(
        _status_only_app,
        config=SecurityConfig(
            enable_redis=False, enable_rate_limiting=False, trusted_proxies=[]
        ),
    )
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/x",
        "raw_path": b"/x",
        "query_string": b"",
        "root_path": "",
        "server": ("t", 80),
        "client": ("203.0.113.5", 5000),
        "headers": [(b"host", b"t")],
    }
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        sent.append(message)

    await app(scope, receive, send)

    start = sent[0]
    names = {key for key, _ in start["headers"]}
    assert start["status"] == 204
    assert b"x-content-type-options" in names
