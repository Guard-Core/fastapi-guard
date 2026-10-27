import asyncio
from collections.abc import (
    AsyncIterable,
    AsyncIterator,
    Awaitable,
    Callable,
    Mapping,
    MutableMapping,
)
from functools import cached_property
from typing import Protocol, runtime_checkable

from guard_core.exceptions import BodyReadStalledError
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse, GuardResponseHeaders
from starlette.datastructures import Headers, State
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import get_route_path
from starlette.types import Message

_Chunk = str | bytes | memoryview


@runtime_checkable
class _BodyStreamingResponse(Protocol):
    # Starlette's StreamingResponse and the response BaseHTTPMiddleware hands to
    # call_next both carry this attribute; a plain Response does not.
    body_iterator: AsyncIterable[_Chunk]


def asgi_scope_as_dict(scope: MutableMapping[str, object]) -> dict[str, object]:
    return scope if isinstance(scope, dict) else dict(scope)


async def _replay_then_continue(
    captured: list[_Chunk], stream: AsyncIterator[_Chunk]
) -> AsyncIterator[_Chunk]:
    for chunk in captured:
        yield chunk
    async for chunk in stream:
        yield chunk


def _join_repeated_header_lines(headers: Headers) -> Headers:
    joined: dict[str, str] = {}
    for key in headers.keys():
        if key not in joined:
            joined[key] = ", ".join(headers.getlist(key))
    raw = [
        (key.encode("latin-1"), value.encode("latin-1"))
        for key, value in joined.items()
    ]
    return Headers(raw=raw)


class StarletteGuardRequest:
    def __init__(self, request: Request) -> None:
        self._request = request

    @property
    def url_path(self) -> str:
        return get_route_path(self._request.scope)

    @property
    def url_scheme(self) -> str:
        return self._request.url.scheme

    @property
    def url_full(self) -> str:
        return str(self._request.url)

    def url_replace_scheme(self, scheme: str) -> str:
        return str(self._request.url.replace(scheme=scheme))

    @property
    def method(self) -> str:
        return self._request.method

    @property
    def client_host(self) -> str | None:
        if self._request.client:
            return self._request.client.host
        return None

    @cached_property
    def headers(self) -> Mapping[str, str]:
        return _join_repeated_header_lines(self._request.headers)

    @property
    def query_params(self) -> Mapping[str, str]:
        return self._request.query_params

    async def body(self) -> bytes:
        return await self._request.body()

    async def read_body_prefix(self, max_bytes: int) -> bytes:
        return await self._read_prefix(max_bytes, None)

    async def read_body_prefix_until_idle(
        self, max_bytes: int, idle_timeout: float
    ) -> bytes:
        return await self._read_prefix(max_bytes, idle_timeout)

    async def _read_prefix(self, max_bytes: int, idle_timeout: float | None) -> bytes:
        if max_bytes <= 0:
            return b""
        cached = getattr(self._request, "_body", None)
        if cached is not None:
            return bytes(cached[:max_bytes])
        if self._request._stream_consumed:
            return b""

        original_receive = self._request._receive
        replay_buffer: list[Message] = []
        in_flight: list[asyncio.Future[Message]] = []

        async def replaying_receive() -> Message:
            if replay_buffer:
                return replay_buffer.pop(0)
            if in_flight:
                return await in_flight.pop()
            return await original_receive()

        self._request._receive = replaying_receive

        collected: list[bytes] = []
        received = 0
        while received < max_bytes:
            message = await self._next_message(
                original_receive, in_flight, idle_timeout
            )
            replay_buffer.append(message)
            if message["type"] != "http.request":
                break
            chunk = message.get("body", b"")
            if chunk:
                collected.append(chunk[: max_bytes - received])
                received += len(chunk)
            if not message.get("more_body", False):
                break
        return b"".join(collected)

    @staticmethod
    async def _next_message(
        receive: Callable[[], Awaitable[Message]],
        in_flight: list[asyncio.Future[Message]],
        idle_timeout: float | None,
    ) -> Message:
        if idle_timeout is None:
            return await receive()
        pending = asyncio.ensure_future(receive())
        done, _ = await asyncio.wait({pending}, timeout=idle_timeout)
        if done:
            return pending.result()
        in_flight.append(pending)
        raise BodyReadStalledError()

    @property
    def state(self) -> State:
        return self._request.state

    @property
    def scope(self) -> dict[str, object]:
        return asgi_scope_as_dict(self._request.scope)


def _chunk_bytes(chunk: _Chunk) -> bytes:
    if isinstance(chunk, bytes):
        return chunk
    if isinstance(chunk, memoryview):
        return bytes(chunk)
    return str(chunk).encode("utf-8", errors="replace")


class StarletteGuardResponse:
    body_is_materialized: bool

    def __init__(self, response: Response) -> None:
        self._response = response
        # Starlette's Response holds ``body`` on the instance; FileResponse and
        # StreamingResponse never do, so this reads no body and starts no stream.
        self.body_is_materialized = "body" in vars(response)

    @property
    def status_code(self) -> int:
        return self._response.status_code

    @property
    def headers(self) -> GuardResponseHeaders:
        return self._response.headers

    @property
    def body(self) -> bytes | None:
        return bytes(self._response.body)

    def _declared_length_within(self, max_bytes: int) -> int | None:
        declared = self._response.headers.get("content-length", "")
        if declared.isascii() and declared.isdigit() and int(declared) <= max_bytes:
            return int(declared)
        return None

    async def read_body_prefix(self, max_bytes: int) -> bytes:
        if max_bytes <= 0:
            return b""
        materialized = getattr(self._response, "body", None)
        if materialized is not None:
            return bytes(materialized)[:max_bytes]
        streaming = self._response
        if not isinstance(streaming, _BodyStreamingResponse):
            return b""

        stream = aiter(streaming.body_iterator)
        captured: list[_Chunk] = []
        streaming.body_iterator = _replay_then_continue(captured, stream)

        # a declared length within the cap is read to its end; any other stream
        # stops at the first chunk, so an endless stream never stalls the scan
        declared = self._declared_length_within(max_bytes)
        received = 0
        while True:
            try:
                chunk = await anext(stream)
            except StopAsyncIteration:
                break
            captured.append(chunk)
            received += len(_chunk_bytes(chunk))
            if declared is None or received >= declared:
                break
        return b"".join(_chunk_bytes(chunk) for chunk in captured)[:max_bytes]


class StarletteResponseFactory:
    def create_response(self, content: str, status_code: int) -> StarletteGuardResponse:
        return StarletteGuardResponse(
            Response(content=content, status_code=status_code, media_type="text/plain")
        )

    def create_redirect_response(
        self, url: str, status_code: int
    ) -> StarletteGuardResponse:
        return StarletteGuardResponse(
            RedirectResponse(url=url, status_code=status_code)
        )


def wrap_call_next(
    call_next: Callable[[Request], Awaitable[Response]],
    starlette_request: Request,
) -> Callable[[GuardRequest], Awaitable[GuardResponse]]:
    async def wrapped(guard_request: GuardRequest) -> GuardResponse:
        response = await call_next(starlette_request)
        return StarletteGuardResponse(response)

    return wrapped


def unwrap_response(guard_response: GuardResponse) -> Response:
    if isinstance(guard_response, StarletteGuardResponse):
        return guard_response._response
    return Response(
        content=guard_response.body,
        status_code=guard_response.status_code,
        headers=dict(guard_response.headers),
    )
