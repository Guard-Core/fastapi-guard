import asyncio
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI, Request
from guard_core.exceptions import BodyReadStalledError
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
from starlette.requests import Request as StarletteRequest

from guard import SecurityConfig
from guard.adapters import StarletteGuardRequest
from guard.middleware import SecurityMiddleware


def _scope() -> dict[str, Any]:
    return {
        "type": "http",
        "method": "POST",
        "path": "/x",
        "root_path": "",
        "query_string": b"",
        "headers": [(b"content-length", b"10")],
        "client": ("127.0.0.1", 5555),
        "scheme": "http",
        "server": ("testserver", 80),
        "state": {},
    }


def _request(receive: Any) -> tuple[StarletteRequest, StarletteGuardRequest]:
    request = StarletteRequest(_scope(), receive)
    return request, StarletteGuardRequest(request)


async def test_the_idle_read_returns_the_prefix_and_replays_it_to_the_app() -> None:
    messages = [
        {"type": "http.request", "body": b"abcde", "more_body": True},
        {"type": "http.request", "body": b"fghij", "more_body": False},
    ]

    async def receive() -> dict[str, Any]:
        return messages.pop(0)

    request, guard_request = _request(receive)

    prefix = await guard_request.read_body_prefix_until_idle(1024, 1.0)

    assert prefix == b"abcdefghij"
    assert await request.body() == b"abcdefghij"


async def test_the_idle_read_stops_at_max_bytes_and_keeps_the_rest() -> None:
    messages = [
        {"type": "http.request", "body": b"abcde", "more_body": True},
        {"type": "http.request", "body": b"fghij", "more_body": False},
    ]

    async def receive() -> dict[str, Any]:
        return messages.pop(0)

    request, guard_request = _request(receive)

    assert await guard_request.read_body_prefix_until_idle(3, 1.0) == b"abc"
    assert await request.body() == b"abcdefghij"


async def test_a_stalled_idle_read_raises_and_loses_no_byte() -> None:
    release = asyncio.Event()
    delivered = False

    async def receive() -> dict[str, Any]:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": b"abc", "more_body": True}
        await release.wait()
        return {"type": "http.request", "body": b"def", "more_body": False}

    request, guard_request = _request(receive)

    with pytest.raises(BodyReadStalledError):
        await guard_request.read_body_prefix_until_idle(1024, 0.05)

    release.set()
    assert await request.body() == b"abcdef"


async def test_the_idle_deadline_restarts_with_every_chunk() -> None:
    sent = 0

    async def receive() -> dict[str, Any]:
        nonlocal sent
        await asyncio.sleep(0.05)
        sent += 1
        return {"type": "http.request", "body": b"x", "more_body": sent < 6}

    _, guard_request = _request(receive)

    started = time.monotonic()
    prefix = await guard_request.read_body_prefix_until_idle(1024, 0.2)

    assert prefix == b"xxxxxx"
    assert time.monotonic() - started > 0.25


async def test_the_older_prefix_method_has_no_deadline() -> None:
    delivered = False

    async def receive() -> dict[str, Any]:
        nonlocal delivered
        if not delivered:
            delivered = True
            await asyncio.sleep(0.2)
        return {"type": "http.request", "body": b"late", "more_body": False}

    _, guard_request = _request(receive)

    assert await guard_request.read_body_prefix(1024) == b"late"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def _serve(app: FastAPI) -> Iterator[int]:
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            proxy_headers=False,
            lifespan="off",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        assert time.time() < deadline, "uvicorn did not start"
        time.sleep(0.02)
    try:
        yield port
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def _echo_app(config: SecurityConfig) -> FastAPI:
    app = FastAPI()

    @app.post("/echo")
    async def echo(request: Request) -> dict[str, int]:
        return {"received": len(await request.body())}

    app.add_middleware(SecurityMiddleware, config=config)
    return app


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": True,
        "enable_rate_limiting": False,
        "fail_secure": True,
        "body_read_timeout": 0.3,
        "ban_on_hostile_signals": False,
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


def _raw_post(
    port: int, chunks: list[tuple[float, bytes]], declared: int = 0
) -> tuple[int, float]:
    body_length = declared or sum(len(chunk) for _, chunk in chunks)
    head = (
        "POST /echo HTTP/1.1\r\nHost: localhost\r\n"
        "Content-Type: text/plain\r\n"
        f"Content-Length: {body_length}\r\nConnection: close\r\n\r\n"
    ).encode()
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(head)
        for pause, chunk in chunks:
            time.sleep(pause)
            try:
                sock.sendall(chunk)
            except OSError:
                break
        data = b""
        while b"\r\n" not in data:
            piece = sock.recv(4096)
            if not piece:
                break
            data += piece
    status = int(data.split(b" ", 2)[1])
    return status, time.monotonic() - started


def test_a_client_that_sends_headers_and_no_body_gets_408_on_a_real_server() -> None:
    with _serve(_echo_app(_config())) as port:
        status, elapsed = _raw_post(port, [], declared=10)

    assert status == 408
    assert elapsed < 1.5


def test_a_slow_client_that_keeps_sending_is_not_cut_off() -> None:
    chunks = [(0.12, b"abcd")] * 6
    with _serve(_echo_app(_config())) as port:
        status, elapsed = _raw_post(port, chunks)

    assert status == 200
    assert elapsed > 0.6


def test_a_stalled_client_passes_unscanned_when_fail_secure_is_off() -> None:
    with _serve(_echo_app(_config(fail_secure=False))) as port:
        status, _ = _raw_post(port, [(0.8, b"0123456789")])

    assert status == 200


def _route_app(config: SecurityConfig) -> FastAPI:
    app = FastAPI()

    @app.get("/shop/cart.php")
    async def cart() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/forum/viewtopic.php")
    async def viewtopic() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/files/{name:path}")
    async def files(name: str) -> dict[str, str]:
        return {"name": name}

    app.add_middleware(SecurityMiddleware, config=config)
    return app


@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("/shop/cart.php", 200),
        ("/forum/viewtopic.php", 200),
        ("/files/shop/cart.php", 400),
        ("/missing/cart.php", 400),
        ("/shop/other.php", 400),
    ],
)
async def test_a_script_path_is_clean_only_when_the_app_declares_it(
    path: str, status: int
) -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        enable_rate_limiting=False,
        ban_on_hostile_signals=False,
    )
    async with AsyncClient(
        transport=ASGITransport(app=_route_app(config)), base_url="http://test"
    ) as client:
        response = await client.get(path)

    assert response.status_code == status


async def test_the_whole_body_is_still_readable_through_the_adapter() -> None:
    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"whole", "more_body": False}

    _, guard_request = _request(receive)

    assert await guard_request.body() == b"whole"
