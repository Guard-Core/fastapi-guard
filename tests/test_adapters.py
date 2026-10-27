import asyncio
import tracemalloc
from collections.abc import AsyncIterator, Callable
from typing import cast

import pytest
from guard_core.protocols import BoundedBodyReader, BoundedResponseBodyReader
from starlette.requests import ClientDisconnect, Request
from starlette.responses import Response, StreamingResponse

from guard.adapters import (
    StarletteGuardRequest,
    StarletteGuardResponse,
    StarletteResponseFactory,
    unwrap_response,
)


async def test_starlette_guard_request_url_path() -> None:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.url_path == "/test"


async def test_starlette_guard_request_url_path_strips_root_path() -> None:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/mounted/api/thing",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "/mounted",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.url_path == "/api/thing"


async def test_starlette_guard_request_method() -> None:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.method == "POST"


async def test_starlette_guard_request_client_host() -> None:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
        "client": ("127.0.0.1", 8000),
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.client_host == "127.0.0.1"


async def test_starlette_guard_request_no_client() -> None:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.client_host is None


async def test_starlette_guard_request_headers() -> None:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [(b"x-custom", b"value")],
        "server": ("localhost", 8000),
        "root_path": "",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.headers.get("x-custom") == "value"


async def test_starlette_guard_request_headers_joins_repeated_field_lines() -> None:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [
            (b"x-forwarded-for", b"66.66.66.1"),
            (b"x-forwarded-for", b"203.0.113.7"),
        ],
        "server": ("localhost", 8000),
        "root_path": "",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.headers.get("x-forwarded-for") == "66.66.66.1, 203.0.113.7"


async def test_starlette_guard_request_headers_items_dedupe_repeated_lines() -> None:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [
            (b"x-forwarded-for", b"66.66.66.1"),
            (b"x-forwarded-for", b"203.0.113.7"),
        ],
        "server": ("localhost", 8000),
        "root_path": "",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert dict(guard_request.headers.items()) == {
        "x-forwarded-for": "66.66.66.1, 203.0.113.7"
    }


async def test_starlette_guard_request_query_params() -> None:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"key=val",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.query_params.get("key") == "val"


async def test_starlette_guard_request_scheme() -> None:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
        "scheme": "https",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.url_scheme == "https"


async def test_starlette_guard_response_properties() -> None:
    response = Response(content="test", status_code=200)
    guard_response = StarletteGuardResponse(response)
    assert guard_response.status_code == 200
    assert guard_response.body == b"test"


async def test_starlette_guard_response_headers() -> None:
    response = Response(content="test", status_code=200)
    guard_response = StarletteGuardResponse(response)
    guard_response.headers["X-Custom"] = "value"
    assert response.headers["X-Custom"] == "value"


async def test_starlette_response_factory_create() -> None:
    factory = StarletteResponseFactory()
    guard_resp = factory.create_response("error", 403)
    assert guard_resp.status_code == 403
    assert guard_resp.body == b"error"


async def test_starlette_response_factory_redirect() -> None:
    factory = StarletteResponseFactory()
    guard_resp = factory.create_redirect_response("https://example.com", 301)
    assert guard_resp.status_code == 301


async def test_unwrap_response_starlette() -> None:
    response = Response(content="test", status_code=200)
    guard_response = StarletteGuardResponse(response)
    unwrapped = unwrap_response(guard_response)
    assert unwrapped is response


async def test_unwrap_response_generic() -> None:
    from unittest.mock import MagicMock

    mock_resp = MagicMock()
    mock_resp.body = b"body"
    mock_resp.status_code = 404
    mock_resp.headers = {"X-Test": "val"}
    unwrapped = unwrap_response(mock_resp)
    assert unwrapped.status_code == 404


async def test_starlette_guard_request_scope() -> None:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    result = guard_request.scope
    assert result["path"] == "/test"
    assert result["method"] == "GET"


def _post_scope() -> dict:
    return {
        "type": "http",
        "method": "POST",
        "path": "/",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
    }


def _scripted_receive(messages: list[dict]) -> tuple[Callable, list[int]]:
    pulls = [0]
    queue = list(messages)

    async def receive() -> dict:
        pulls[0] += 1
        return queue.pop(0)

    return receive, pulls


async def test_guard_request_satisfies_bounded_body_reader_protocol() -> None:
    request = Request(_post_scope())
    assert isinstance(StarletteGuardRequest(request), BoundedBodyReader)


async def test_read_body_prefix_returns_prefix_of_multi_chunk_body() -> None:
    receive, _ = _scripted_receive(
        [
            {"type": "http.request", "body": b"abcd", "more_body": True},
            {"type": "http.request", "body": b"efgh", "more_body": True},
            {"type": "http.request", "body": b"ijkl", "more_body": False},
        ]
    )
    guard_request = StarletteGuardRequest(Request(_post_scope(), receive))
    assert await guard_request.read_body_prefix(6) == b"abcdef"


async def test_read_body_prefix_stops_pulling_at_max_bytes() -> None:
    receive, pulls = _scripted_receive(
        [
            {"type": "http.request", "body": b"abcd", "more_body": True},
            {"type": "http.request", "body": b"efgh", "more_body": True},
            {"type": "http.request", "body": b"ijkl", "more_body": False},
        ]
    )
    guard_request = StarletteGuardRequest(Request(_post_scope(), receive))
    await guard_request.read_body_prefix(4)
    assert pulls[0] == 1


async def test_read_body_prefix_preserves_full_body_for_downstream() -> None:
    receive, _ = _scripted_receive(
        [
            {"type": "http.request", "body": b"abcdefgh", "more_body": True},
            {"type": "http.request", "body": b"ijkl", "more_body": False},
        ]
    )
    request = Request(_post_scope(), receive)
    guard_request = StarletteGuardRequest(request)
    assert await guard_request.read_body_prefix(3) == b"abc"
    assert await request.body() == b"abcdefghijkl"


async def test_read_body_prefix_serves_cached_body_without_receive() -> None:
    receive, pulls = _scripted_receive(
        [{"type": "http.request", "body": b"cached-body", "more_body": False}]
    )
    request = Request(_post_scope(), receive)
    await request.body()
    pulls_after_body = pulls[0]
    guard_request = StarletteGuardRequest(request)
    assert await guard_request.read_body_prefix(6) == b"cached"
    assert pulls[0] == pulls_after_body


async def test_read_body_prefix_short_body_returned_whole() -> None:
    receive, _ = _scripted_receive(
        [{"type": "http.request", "body": b"tiny", "more_body": False}]
    )
    guard_request = StarletteGuardRequest(Request(_post_scope(), receive))
    assert await guard_request.read_body_prefix(1024) == b"tiny"


async def test_read_body_prefix_zero_max_bytes_reads_nothing() -> None:
    receive, pulls = _scripted_receive(
        [{"type": "http.request", "body": b"data", "more_body": False}]
    )
    guard_request = StarletteGuardRequest(Request(_post_scope(), receive))
    assert await guard_request.read_body_prefix(0) == b""
    assert pulls[0] == 0


async def test_read_body_prefix_returns_partial_data_on_disconnect() -> None:
    receive, _ = _scripted_receive(
        [
            {"type": "http.request", "body": b"partial", "more_body": True},
            {"type": "http.disconnect"},
        ]
    )
    request = Request(_post_scope(), receive)
    guard_request = StarletteGuardRequest(request)
    assert await guard_request.read_body_prefix(1024) == b"partial"
    with pytest.raises(ClientDisconnect):
        await request.body()


async def test_read_body_prefix_after_consumed_stream_returns_empty() -> None:
    receive, _ = _scripted_receive(
        [{"type": "http.request", "body": b"gone", "more_body": False}]
    )
    request = Request(_post_scope(), receive)
    async for _chunk in request.stream():
        pass
    guard_request = StarletteGuardRequest(request)
    assert await guard_request.read_body_prefix(1024) == b""


async def _collect_chunks(
    response: StreamingResponse,
) -> list[bytes | str | memoryview]:
    return [chunk async for chunk in response.body_iterator]


async def test_guard_response_satisfies_bounded_response_body_reader_protocol() -> None:
    response = Response(content="ok", status_code=200)
    assert isinstance(StarletteGuardResponse(response), BoundedResponseBodyReader)


async def test_response_read_body_prefix_plain_response_returns_prefix() -> None:
    response = Response(content="plain-body-content", status_code=200)
    guard_response = StarletteGuardResponse(response)
    assert await guard_response.read_body_prefix(5) == b"plain"
    assert response.body == b"plain-body-content"


async def test_response_read_body_prefix_streaming_returns_first_chunk() -> None:
    async def chunks() -> AsyncIterator[bytes]:
        yield b"first-chunk"
        yield b"second-chunk"

    response = StreamingResponse(chunks())
    guard_response = StarletteGuardResponse(response)
    assert await guard_response.read_body_prefix(1024) == b"first-chunk"


async def test_response_read_body_prefix_streaming_preserves_all_chunks() -> None:
    async def chunks() -> AsyncIterator[bytes]:
        yield b"first-chunk"
        yield b"second-chunk"
        yield b"third-chunk"

    response = StreamingResponse(chunks())
    guard_response = StarletteGuardResponse(response)
    await guard_response.read_body_prefix(1024)
    delivered = await _collect_chunks(response)
    assert delivered == [b"first-chunk", b"second-chunk", b"third-chunk"]


async def test_response_read_body_prefix_never_pulls_a_second_chunk() -> None:
    async def indefinite_stream() -> AsyncIterator[bytes]:
        yield b"event: ping\n\n"
        await asyncio.Event().wait()
        yield b"never"

    response = StreamingResponse(indefinite_stream())
    guard_response = StarletteGuardResponse(response)
    prefix = await asyncio.wait_for(guard_response.read_body_prefix(1024), timeout=0.5)
    assert prefix == b"event: ping\n\n"


async def test_response_read_body_prefix_str_chunks_scanned_and_replayed() -> None:
    async def chunks() -> AsyncIterator[str]:
        yield "text-chunk"
        yield "more-text"

    response = StreamingResponse(chunks())
    guard_response = StarletteGuardResponse(response)
    assert await guard_response.read_body_prefix(1024) == b"text-chunk"
    assert await _collect_chunks(response) == ["text-chunk", "more-text"]


async def test_response_read_body_prefix_empty_stream_returns_empty() -> None:
    async def no_chunks() -> AsyncIterator[bytes]:
        empty: tuple[bytes, ...] = ()
        for chunk in empty:
            yield chunk

    response = StreamingResponse(no_chunks())
    guard_response = StarletteGuardResponse(response)
    assert await guard_response.read_body_prefix(1024) == b""
    assert await _collect_chunks(response) == []


async def test_response_read_body_prefix_zero_max_bytes_reads_nothing() -> None:
    async def chunks() -> AsyncIterator[bytes]:
        yield b"untouched"

    response = StreamingResponse(chunks())
    guard_response = StarletteGuardResponse(response)
    assert await guard_response.read_body_prefix(0) == b""
    assert await _collect_chunks(response) == [b"untouched"]


async def test_response_read_body_prefix_slices_oversized_first_chunk() -> None:
    async def chunks() -> AsyncIterator[bytes]:
        yield b"abcdefghij"

    response = StreamingResponse(chunks())
    guard_response = StarletteGuardResponse(response)
    assert await guard_response.read_body_prefix(4) == b"abcd"
    assert await _collect_chunks(response) == [b"abcdefghij"]


async def test_read_body_prefix_skips_empty_chunks_mid_stream() -> None:
    receive, _ = _scripted_receive(
        [
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.request", "body": b"", "more_body": True},
            {"type": "http.request", "body": b"def", "more_body": False},
        ]
    )
    request = Request(_post_scope(), receive)
    guard_request = StarletteGuardRequest(request)
    assert await guard_request.read_body_prefix(1024) == b"abcdef"
    assert await request.body() == b"abcdef"


async def test_response_read_body_prefix_memoryview_chunk_scanned_as_bytes() -> None:
    async def chunks() -> AsyncIterator[memoryview]:
        yield memoryview(b"view-chunk")

    response = StreamingResponse(chunks())
    guard_response = StarletteGuardResponse(response)
    assert await guard_response.read_body_prefix(1024) == b"view-chunk"


async def test_response_read_body_prefix_without_body_or_iterator() -> None:
    class _BareResponse:
        status_code = 204
        headers: dict[str, str] = {}

    guard_response = StarletteGuardResponse(cast(Response, _BareResponse()))
    assert await guard_response.read_body_prefix(1024) == b""


async def test_read_body_prefix_bounds_aggregation_for_oversized_message() -> None:
    oversized = b"x" * (8 * 1024 * 1024)
    receive, _ = _scripted_receive(
        [{"type": "http.request", "body": oversized, "more_body": False}]
    )
    request = Request(_post_scope(), receive)
    guard_request = StarletteGuardRequest(request)

    tracemalloc.start()
    prefix = await guard_request.read_body_prefix(4096)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert prefix == oversized[:4096]
    assert peak < 1024 * 1024
    assert await request.body() == oversized


async def test_read_body_prefix_transient_copies_stay_below_body_size() -> None:
    first = b"y" * (4 * 1024 * 1024)
    second = b"z" * (4 * 1024 * 1024)
    receive, _ = _scripted_receive(
        [
            {"type": "http.request", "body": first, "more_body": True},
            {"type": "http.request", "body": second, "more_body": False},
        ]
    )
    request = Request(_post_scope(), receive)
    guard_request = StarletteGuardRequest(request)

    tracemalloc.start()
    prefix = await guard_request.read_body_prefix(5 * 1024 * 1024)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert prefix == (first + second)[: 5 * 1024 * 1024]
    assert peak < 8 * 1024 * 1024
    assert await request.body() == first + second


def test_asgi_scope_as_dict_keeps_a_dict_and_copies_any_other_mapping() -> None:
    from collections import UserDict

    from guard.adapters import asgi_scope_as_dict

    scope: dict[str, object] = {"type": "http"}

    assert asgi_scope_as_dict(scope) is scope
    assert asgi_scope_as_dict(UserDict(scope)) == scope
