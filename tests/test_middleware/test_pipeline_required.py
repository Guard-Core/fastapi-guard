import pytest
from fastapi import FastAPI
from guard_core.models import SecurityConfig
from starlette.requests import Request

from guard.adapters import StarletteGuardRequest
from guard.middleware import SecurityMiddleware


def _request(method: str, headers: list[tuple[bytes, bytes]]) -> Request:
    return Request(
        {
            "type": "http",
            "method": method,
            "path": "/",
            "headers": headers,
            "query_string": b"",
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
            "scheme": "http",
        }
    )


def _uninitialized_middleware() -> SecurityMiddleware:
    config = SecurityConfig(enable_redis=False, enable_cors=True)
    middleware = SecurityMiddleware(FastAPI(), config=config)
    assert middleware.security_pipeline is None
    return middleware


async def test_pipeline_block_before_initialization_raises_runtime_error() -> None:
    middleware = _uninitialized_middleware()
    request = _request("GET", [])

    with pytest.raises(RuntimeError, match="security pipeline is not built"):
        await middleware._handle_pipeline_block(request, StarletteGuardRequest(request))


async def test_preflight_before_initialization_raises_runtime_error() -> None:
    middleware = _uninitialized_middleware()
    request = _request(
        "OPTIONS",
        [
            (b"origin", b"https://example.com"),
            (b"access-control-request-method", b"GET"),
        ],
    )

    with pytest.raises(RuntimeError, match="security pipeline is not built"):
        await middleware._handle_preflight(request, StarletteGuardRequest(request))
