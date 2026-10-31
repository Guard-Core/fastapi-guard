import asyncio
from typing import Any

import pytest
from fastapi import FastAPI, Request
from guard_core.models import SecurityConfig
from starlette.types import ASGIApp, Message

from guard import PureASGISecurityMiddleware, SecurityMiddleware

MiddlewareClass = type[SecurityMiddleware] | type[PureASGISecurityMiddleware]


def _app(middleware: MiddlewareClass) -> FastAPI:
    config = SecurityConfig(
        enable_redis=False,
        enable_rate_limiting=False,
        fail_secure=False,
        body_read_timeout=0.2,
        trusted_proxies=(),
    )
    app = FastAPI()
    app.add_middleware(middleware, config=config)

    @app.post("/echo")
    async def echo(request: Request) -> dict[str, int]:
        return {"received": len(await request.body())}

    return app


async def _drive(app: ASGIApp, chunks: list[tuple[float, bytes]]) -> dict[str, Any]:
    length = sum(len(chunk) for _, chunk in chunks)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/echo",
        "raw_path": b"/echo",
        "query_string": b"",
        "root_path": "",
        "server": ("t", 80),
        "client": ("203.0.113.5", 5000),
        "headers": [
            (b"host", b"t"),
            (b"content-type", b"text/plain"),
            (b"content-length", str(length).encode()),
        ],
        "app": app,
    }
    sent = 0

    async def receive() -> Message:
        nonlocal sent
        if sent >= len(chunks):
            await asyncio.sleep(0.3)
            return {"type": "http.disconnect"}
        delay, data = chunks[sent]
        sent += 1
        await asyncio.sleep(delay)
        return {"type": "http.request", "body": data, "more_body": sent < len(chunks)}

    out: dict[str, Any] = {}

    async def send(message: Message) -> None:
        if message["type"] == "http.response.start":
            out["status"] = message["status"]
        elif message["type"] == "http.response.body":
            out["body"] = out.get("body", b"") + message.get("body", b"")

    await asyncio.wait_for(app(scope, receive, send), 8)
    return out


@pytest.mark.parametrize("middleware", [SecurityMiddleware, PureASGISecurityMiddleware])
async def test_a_chunk_that_arrives_after_the_idle_deadline_reaches_the_app(
    middleware: MiddlewareClass,
) -> None:
    out = await _drive(_app(middleware), [(0, b"a" * 10), (0.6, b"b" * 10)])

    assert (out["status"], out["body"]) == (200, b'{"received":20}')
