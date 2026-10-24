"""The response wrapper declares whether the body is in memory, and tees a stream.

The engine reads ``body_is_materialized`` once per response (guard-core
``ErrorResponseFactory.apply_modifier``): True hands the modifier the real
response, anything else takes the bounded path through ``read_body_prefix``.
"""

import asyncio
import hashlib
import itertools
import logging
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi import FastAPI
from guard_core.core.responses import reads_response_body
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
from starlette.middleware.base import _StreamingResponse
from starlette.requests import Request
from starlette.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)

from guard import SecurityConfig
from guard.adapters import StarletteGuardRequest, StarletteGuardResponse
from guard.middleware import SecurityMiddleware

_IP = itertools.count(1)
_BODY = bytes(range(256)) * 40
_CAP = 262144


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unique_ip() -> str:
    n = next(_IP)
    return f"198.19.{n // 250}.{(n % 250) + 1}"


class _Pulled:
    def __init__(self) -> None:
        self.chunks = 0


def _counting_stream(chunks: list[bytes], pulled: _Pulled) -> AsyncIterator[bytes]:
    async def generate() -> AsyncIterator[bytes]:
        for chunk in chunks:
            pulled.chunks += 1
            yield chunk

    return generate()


def _split(body: bytes, size: int) -> list[bytes]:
    return [body[i : i + size] for i in range(0, len(body), size)]


async def _drain(response: Response) -> bytes:
    sent: list[bytes] = []

    async def send(message: Any) -> None:
        if message["type"] == "http.response.body":
            sent.append(message.get("body", b""))

    async def receive() -> Any:
        # Starlette 1.8 stops a FileResponse once receive() reports a disconnect.
        await asyncio.Event().wait()

    await response({"type": "http", "method": "GET", "headers": []}, receive, send)
    return b"".join(sent)


def _native_responses(path: Path) -> dict[str, Response]:
    path.write_bytes(_BODY)
    return {
        "Response": Response(_BODY),
        "JSONResponse": JSONResponse({"a": 1}),
        "PlainTextResponse": PlainTextResponse("x"),
        "HTMLResponse": HTMLResponse("<p>x</p>"),
        "RedirectResponse": RedirectResponse("/elsewhere"),
        "FileResponse": FileResponse(path),
        "StreamingResponse": StreamingResponse(_counting_stream([b"a"], _Pulled())),
        "_StreamingResponse": _StreamingResponse(
            _counting_stream([b"a"], _Pulled()), status_code=200
        ),
    }


_MATERIALIZED = {
    "Response": True,
    "JSONResponse": True,
    "PlainTextResponse": True,
    "HTMLResponse": True,
    "RedirectResponse": True,
    "FileResponse": False,
    "StreamingResponse": False,
    "_StreamingResponse": False,
}


@pytest.mark.parametrize("name", sorted(_MATERIALIZED))
def test_the_capability_matches_the_native_response_type(name: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        native = _native_responses(Path(tmp) / "file.bin")[name]
        assert (
            StarletteGuardResponse(native).body_is_materialized is _MATERIALIZED[name]
        )


def test_reading_the_capability_pulls_no_chunk_and_touches_no_body() -> None:
    pulled = _Pulled()
    native = StreamingResponse(_counting_stream([b"a", b"b"], pulled))
    wrapper = StarletteGuardResponse(native)
    assert wrapper.body_is_materialized is False
    assert wrapper.body_is_materialized is False
    assert pulled.chunks == 0


class _Seen:
    def __init__(self) -> None:
        self.calls = 0
        self.body: bytes | None = None
        self.refused = False


def _modifier(seen: _Seen) -> Any:
    @reads_response_body
    async def modifier(response: Any) -> Any:
        seen.calls += 1
        try:
            seen.body = response.body
        except AttributeError:
            seen.refused = True
        response.headers["x-modified"] = "1"
        return response

    return modifier


def _engine(modifier: Any, **overrides: Any) -> ErrorResponseFactory:
    config = SecurityConfig(enable_redis=False, **overrides)
    config.custom_response_modifier = modifier
    return ErrorResponseFactory(
        ResponseContext(
            config=config,
            logger=logging.getLogger("guard.test_response_body_capability"),
            metrics_collector=MagicMock(collect_request_metrics=AsyncMock()),
            response_factory=None,
        )
    )


def _request() -> StarletteGuardRequest:
    return StarletteGuardRequest(
        Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/",
                "query_string": b"",
                "headers": [],
                "client": ("127.0.0.1", 1),
            }
        )
    )


async def test_a_modifier_on_memory_gets_the_real_bytes_in_one_call() -> None:
    seen = _Seen()
    native = Response(_BODY * 30)
    assert len(_BODY * 30) > _CAP
    result = await _engine(_modifier(seen)).apply_modifier(
        StarletteGuardResponse(native), _request()
    )
    assert seen.calls == 1
    assert seen.body == _BODY * 30
    assert not seen.refused
    assert isinstance(result, StarletteGuardResponse)
    assert native.headers["x-modified"] == "1"


async def test_a_modifier_on_a_declared_stream_under_the_cap_gets_every_byte() -> None:
    seen = _Seen()
    pulled = _Pulled()
    chunks = _split(_BODY, 1000)
    native = StreamingResponse(
        _counting_stream(chunks, pulled), headers={"content-length": str(len(_BODY))}
    )
    await _engine(_modifier(seen)).apply_modifier(
        StarletteGuardResponse(native), _request()
    )
    assert seen.body == _BODY
    assert pulled.chunks == len(chunks)
    assert _sha(await _drain(native)) == _sha(_BODY)


async def test_a_modifier_on_an_undeclared_stream_is_refused_and_nothing_is_lost() -> (
    None
):
    seen = _Seen()
    pulled = _Pulled()
    chunks = _split(_BODY, 1000)
    native = StreamingResponse(_counting_stream(chunks, pulled))
    await _engine(_modifier(seen)).apply_modifier(
        StarletteGuardResponse(native), _request()
    )
    assert seen.refused
    assert seen.calls == 1
    assert native.headers["x-modified"] == "1"
    assert pulled.chunks == 0
    assert _sha(await _drain(native)) == _sha(_BODY)


async def test_a_modifier_on_a_file_response_is_refused_and_the_file_is_delivered() -> (
    None
):
    seen = _Seen()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "file.bin"
        path.write_bytes(_BODY)
        native = FileResponse(path)
        wrapper = StarletteGuardResponse(native)
        assert wrapper.body_is_materialized is False
        await _engine(_modifier(seen)).apply_modifier(wrapper, _request())
        assert seen.refused
        assert seen.calls == 1
        assert native.headers["x-modified"] == "1"
        assert _sha(await _drain(native)) == _sha(_BODY)


async def test_a_stalled_declared_stream_is_bounded_and_does_not_hang() -> None:
    seen = _Seen()

    async def stalls_after_the_first_chunk() -> AsyncIterator[bytes]:
        yield b"first"
        await asyncio.sleep(30)
        yield b"never"

    native = StreamingResponse(
        stalls_after_the_first_chunk(), headers={"content-length": "10"}
    )
    await asyncio.wait_for(
        _engine(_modifier(seen), body_read_timeout=0.1).apply_modifier(
            StarletteGuardResponse(native), _request()
        ),
        timeout=5,
    )
    assert seen.refused
    assert seen.calls == 1


async def test_read_body_prefix_reads_a_declared_length_to_its_end_and_replays_it() -> (
    None
):
    chunks = _split(_BODY, 700)
    native = StreamingResponse(
        _counting_stream(chunks, _Pulled()),
        headers={"content-length": str(len(_BODY))},
    )
    prefix = await StarletteGuardResponse(native).read_body_prefix(_CAP)
    assert prefix == _BODY
    assert _sha(await _drain(native)) == _sha(_BODY)


async def test_read_body_prefix_stops_at_the_declared_length_not_the_stream_end() -> (
    None
):
    pulled = _Pulled()
    chunks = _split(_BODY, 1000)
    native = StreamingResponse(
        _counting_stream(chunks, pulled), headers={"content-length": "2500"}
    )
    prefix = await StarletteGuardResponse(native).read_body_prefix(_CAP)
    assert prefix == _BODY[:3000][:_CAP]
    assert pulled.chunks == 3
    assert _sha(await _drain(native)) == _sha(_BODY)


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"content-length": "abc"},
        {"content-length": " 10"},
        {"content-length": "999999"},
    ],
)
async def test_read_body_prefix_stops_at_the_first_chunk_without_a_usable_length(
    headers: dict[str, str],
) -> None:
    pulled = _Pulled()
    chunks = _split(_BODY, 1000)
    native = StreamingResponse(_counting_stream(chunks, pulled), headers=headers)
    prefix = await StarletteGuardResponse(native).read_body_prefix(1500)
    assert prefix == chunks[0]
    assert pulled.chunks == 1
    assert _sha(await _drain(native)) == _sha(_BODY)


async def test_read_body_prefix_counts_text_and_memoryview_chunks_in_bytes() -> None:
    async def mixed() -> AsyncIterator[Any]:
        yield "éa"
        yield memoryview(b"bc")
        yield b"d"

    native = StreamingResponse(mixed(), headers={"content-length": "6"})
    prefix = await StarletteGuardResponse(native).read_body_prefix(_CAP)
    assert prefix == "éabcd".encode()


async def test_read_body_prefix_returns_what_a_short_declared_stream_produced() -> None:
    native = StreamingResponse(
        _counting_stream([b"ab"], _Pulled()), headers={"content-length": "50"}
    )
    assert await StarletteGuardResponse(native).read_body_prefix(_CAP) == b"ab"
    assert await _drain(native) == b"ab"


def _app(config: SecurityConfig, path: Path) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/memory")
    async def memory() -> Response:
        return Response(_BODY)

    @app.get("/stream-declared")
    async def stream_declared() -> StreamingResponse:
        return StreamingResponse(
            _counting_stream(_split(_BODY, 900), _Pulled()),
            headers={"content-length": str(len(_BODY))},
        )

    @app.get("/stream-undeclared")
    async def stream_undeclared() -> StreamingResponse:
        return StreamingResponse(_counting_stream(_split(_BODY, 900), _Pulled()))

    @app.get("/sse")
    async def sse() -> StreamingResponse:
        return StreamingResponse(
            _counting_stream(_split(_BODY, 900), _Pulled()),
            media_type="text/event-stream",
            headers={"content-length": str(len(_BODY))},
        )

    @app.get("/file")
    async def file() -> FileResponse:
        return FileResponse(path)

    return app


async def _get(path_name: str, seen: _Seen) -> httpx.Response:
    config = SecurityConfig(enable_redis=False)
    config.custom_response_modifier = _modifier(seen)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "file.bin"
        path.write_bytes(_BODY)
        transport = ASGITransport(app=_app(config, path), client=(_unique_ip(), 5))
        async with AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.get(path_name)


@pytest.mark.parametrize(
    ("route", "readable"),
    [
        ("/memory", True),
        ("/stream-declared", True),
        ("/stream-undeclared", False),
        ("/sse", False),
        ("/file", True),
    ],
)
async def test_through_the_middleware_the_client_gets_every_byte(
    route: str, readable: bool
) -> None:
    seen = _Seen()
    response = await _get(route, seen)
    assert response.status_code == 200
    assert response.headers["x-modified"] == "1"
    assert _sha(response.content) == _sha(_BODY)
    assert seen.calls == 1
    assert seen.refused is not readable
    assert (seen.body == _BODY) is readable
