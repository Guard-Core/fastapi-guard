"""The bounded response capture the pure ASGI middleware feeds to behavior rules."""

from types import SimpleNamespace
from typing import Any, cast

from starlette.requests import Request

from guard.asgi import _CapturedResponse, _HeaderInjectingSend
from guard.middleware import SecurityMiddleware


async def _noop_send(message: Any) -> None:
    return None


def _send_with(scan: bool, cap: int) -> _HeaderInjectingSend:
    engine = SimpleNamespace(
        config=SimpleNamespace(
            behavior_scan_response_body=scan,
            behavior_max_response_body_inspect_bytes=cap,
        )
    )
    request = Request({"type": "http", "headers": []})
    return _HeaderInjectingSend(
        _noop_send, engine=cast(SecurityMiddleware, engine), request=request
    )


async def test_body_chunks_are_not_kept_when_body_scanning_is_off() -> None:
    send = _send_with(scan=False, cap=10)
    await send({"type": "http.response.body", "body": b"abcdef"})
    assert send.body_prefix == b""


async def test_body_prefix_stops_at_the_cap_across_chunks() -> None:
    send = _send_with(scan=True, cap=5)
    await send({"type": "http.response.body", "body": b"abc"})
    await send({"type": "http.response.body", "body": b"defgh"})
    await send({"type": "http.response.body", "body": b"ijk"})
    assert send.body_prefix == b"abcde"


async def test_captured_response_exposes_status_headers_and_a_bounded_prefix() -> None:
    response = _CapturedResponse(404, {"content-type": "text/plain"}, b"abcdef")
    assert response.status_code == 404
    assert response.headers == {"content-type": "text/plain"}
    assert response.body is None
    assert await response.read_body_prefix(3) == b"abc"


async def test_other_message_types_pass_through_untouched() -> None:
    send = _send_with(scan=True, cap=5)
    await send({"type": "http.response.trailers", "headers": []})
    assert send.body_prefix == b""
