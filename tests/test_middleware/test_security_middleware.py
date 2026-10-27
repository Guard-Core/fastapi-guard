import asyncio
import json
import logging
import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from guard_core.detection_result import DetectionResult
from guard_core.exceptions import GuardRedisError
from guard_core.handlers.cloud_handler import cloud_handler_for
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.ratelimit_handler import rate_limit_handler
from guard_core.handlers.redis_handler import redis_handler
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.models import SecurityConfig
from guard_core.protocols import GuardRequest, GuardResponse
from guard_core.utils import IpAccessResult
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
from redis.exceptions import RedisError
from starlette.applications import Starlette
from starlette.routing import Match, Route
from starlette.testclient import TestClient

from guard.adapters import StarletteGuardRequest, StarletteGuardResponse
from guard.middleware import SecurityMiddleware


def assert_log_activity_called_with(mock_log: Mock, **expected_kwargs: Any) -> None:
    assert any(
        expected_kwargs.items() <= call.kwargs.items()
        for call in mock_log.call_args_list
    ), f"No call to {mock_log} had kwargs matching {expected_kwargs}"


@pytest.mark.asyncio
async def test_rate_limiting() -> None:
    """
    Test the rate limiting functionality
    of the SecurityMiddleware.
    """
    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        rate_limit=2,
        rate_limit_window=1,
        enable_rate_limiting=True,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/")
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        middleware = _serving_middleware(app)
        await middleware.rate_limit_handler.reset()

        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_ip_whitelist_blacklist() -> None:
    """
    Test the IP whitelist/blacklist
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()
    config = SecurityConfig(
        whitelist=("127.0.0.1",),
        blacklist=("192.168.1.1",),
        enable_penetration_detection=False,
        trusted_proxies=("127.0.0.1",),
    )

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"X-Forwarded-For": "127.0.0.1"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
        assert response.status_code == status.HTTP_403_FORBIDDEN

        response = await client.get("/", headers={"X-Forwarded-For": "10.0.0.1"})
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_rate_limiting_is_keyed_on_the_joined_right_most_forwarded_entry() -> (
    None
):
    """
    A client that sends its own X-Forwarded-For line ahead of the real
    proxy-appended one must not be able to rotate the left entry to evade
    rate limiting; the right-most (depth=1) entry of the joined chain is
    what guard-core resolves as the client.
    """
    import httpx2

    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        trusted_proxies=("10.0.0.1",),
        trusted_proxy_depth=1,
        rate_limit=3,
        rate_limit_window=60,
        enable_rate_limiting=True,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with TestClient(app, client=("10.0.0.1", 5000)) as client:
        statuses = []
        for i in range(9):
            request = httpx2.Request(
                "GET",
                "http://testserver/",
                headers=[
                    (b"host", b"testserver"),
                    (b"x-forwarded-for", f"66.66.66.{i}".encode()),
                    (b"x-forwarded-for", b"203.0.113.7"),
                ],
            )
            statuses.append(client.send(request).status_code)

        assert client.portal is not None
        client.portal.call(redis_handler(config).close)

    assert statuses[:3] == [200, 200, 200]
    assert all(status == 429 for status in statuses[3:])


@pytest.mark.asyncio
async def test_user_agent_filtering() -> None:
    """
    Test the user agent filtering
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        blocked_user_agents=[r"badbot"],
    )

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"User-Agent": "goodbot"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"User-Agent": "badbot"})
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_rate_limiting_multiple_ips(reset_state: None) -> None:
    """
    Test the rate limiting functionality
    of the SecurityMiddleware with multiple IPs.
    """
    app = FastAPI()
    config = SecurityConfig(
        rate_limit=2,
        rate_limit_window=1,
        enable_rate_limiting=True,
        whitelist=(),
        blacklist=(),
        enable_penetration_detection=False,
        trusted_proxies=("127.0.0.1",),
    )

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        for i in range(1, 4):
            response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
            assert response.status_code == (
                status.HTTP_200_OK if i <= 2 else status.HTTP_429_TOO_MANY_REQUESTS
            )

        for i in range(1, 4):
            response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.5"})
            assert response.status_code == (
                status.HTTP_200_OK if i <= 2 else status.HTTP_429_TOO_MANY_REQUESTS
            )

        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.5"})
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS


@pytest.mark.asyncio
async def test_middleware_multiple_configs() -> None:
    """
    Test the SecurityMiddleware
    with multiple configurations.
    """
    app = FastAPI()
    config1 = SecurityConfig(
        blocked_user_agents=[r"badbot"],
        enable_penetration_detection=False,
        trusted_proxies=("127.0.0.1",),
    )

    config2 = SecurityConfig(
        whitelist=("127.0.0.1",),
        blacklist=("192.168.1.1",),
        enable_penetration_detection=False,
        trusted_proxies=("127.0.0.1",),
    )

    app.add_middleware(SecurityMiddleware, config=config1)
    app.add_middleware(SecurityMiddleware, config=config2)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"User-Agent": "badbot"})
        assert response.status_code == status.HTTP_403_FORBIDDEN

        response = await client.get("/", headers={"X-Forwarded-For": "127.0.0.1"})
        assert response.status_code == status.HTTP_200_OK
        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_custom_request_check() -> None:
    """
    Test the custom request check
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()

    async def custom_check(request: GuardRequest) -> GuardResponse | None:
        if request.headers.get("X-Custom-Header") == "block":
            return StarletteGuardResponse(
                Response("Custom block", status_code=status.HTTP_403_FORBIDDEN)
            )
        return None

    config = SecurityConfig(
        enable_penetration_detection=False,
        custom_request_check=custom_check,
    )

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"X-Custom-Header": "block"})
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.text == "Custom block"

        response = await client.get("/", headers={"X-Custom-Header": "allow"})
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_custom_error_responses() -> None:
    """
    Test the custom error responses.
    """
    app = FastAPI()
    config = SecurityConfig(
        blacklist=("192.168.1.3",),
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        rate_limit=5,
        rate_limit_window=1,
        auto_ban_threshold=10,
        enable_penetration_detection=False,
        trusted_proxies=("127.0.0.1",),
    )

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.3"})
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.text == "Custom Forbidden"

        for _ in range(5):
            response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.4"})
            assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.4"})
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert response.text == "Custom Too Many Requests"


@pytest.mark.parametrize(
    (
        "test_scenario, expected_status_code, extra_config, "
        "request_path, request_headers, use_custom_check"
    ),
    [
        # NOTE: Normal case
        (
            "normal",
            status.HTTP_200_OK,
            {},
            "/",
            {},
            False,
        ),
        # NOTE: Blacklisted IP
        (
            "blacklisted",
            status.HTTP_403_FORBIDDEN,
            {},
            "/",
            {"X-Forwarded-For": "192.168.1.5"},
            False,
        ),
        # NOTE: HTTPS enforcement
        (
            "https_enforcement",
            status.HTTP_301_MOVED_PERMANENTLY,
            {"enforce_https": True},
            "/",
            {},
            False,
        ),
        # NOTE: Excluded path
        (
            "excluded_path",
            status.HTTP_200_OK,
            {"exclude_paths": ["/excluded"]},
            "/excluded",
            {},
            False,
        ),
        # NOTE: Custom request check
        (
            "custom_request_check",
            status.HTTP_418_IM_A_TEAPOT,
            {},
            "/",
            {"X-Custom-Check": "true"},
            True,
        ),
        # NOTE: Custom request check - no trigger
        (
            "custom_request_check_no_trigger",
            status.HTTP_200_OK,
            {},
            "/",
            {},
            True,
        ),
        (
            "no_client_info_fail_secure_rejects",
            status.HTTP_403_FORBIDDEN,
            {},
            "/",
            {},
            False,
        ),
        (
            "no_client_info_fail_secure_false_runs_as_unknown",
            status.HTTP_200_OK,
            {"fail_secure": False},
            "/",
            {},
            False,
        ),
        (
            "no_client_info_fail_secure_false_whitelist_still_rejects",
            status.HTTP_403_FORBIDDEN,
            {"fail_secure": False, "whitelist": ["10.0.0.0/8"]},
            "/",
            {},
            False,
        ),
    ],
)
@pytest.mark.asyncio
async def test_custom_response_modifier_parameterized(
    test_scenario: str,
    expected_status_code: int,
    extra_config: dict[str, Any],
    request_path: str,
    request_headers: dict[str, str],
    use_custom_check: bool,
) -> None:
    """
    Parameterized test for the custom response modifier covering all scenarios.
    """
    app = FastAPI()

    async def custom_modifier(response: GuardResponse) -> GuardResponse:
        response.headers["X-Modified"] = "True"
        if response.status_code >= 400:
            body = response.body or b""
            return StarletteGuardResponse(
                JSONResponse(
                    status_code=response.status_code,
                    content={"detail": body.decode()},
                    headers={"X-Modified": "True"},
                )
            )
        return response

    async def custom_check(request: GuardRequest) -> GuardResponse | None:
        if "X-Custom-Check" in request.headers:
            return StarletteGuardResponse(
                Response("I'm a teapot", status_code=status.HTTP_418_IM_A_TEAPOT)
            )
        return None

    config_args: dict[str, Any] = {
        "enable_penetration_detection": False,
        "blacklist": ["192.168.1.5"],
        "custom_response_modifier": custom_modifier,
        "trusted_proxies": ["127.0.0.1"],
    }

    if use_custom_check:
        config_args["custom_request_check"] = custom_check

    config_args.update(extra_config)
    config = SecurityConfig(**config_args)

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    @app.get("/excluded")
    async def excluded_path() -> dict[str, str]:
        return {"message": "Excluded Path"}

    if test_scenario.startswith("no_client_info"):

        async def receive() -> dict[str, str | bytes]:
            return {"type": "http.request", "body": b""}

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [
                (k.lower().encode(), v.encode()) for k, v in request_headers.items()
            ],
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
        }

        request = Request(scope=scope, receive=receive)

        body = await request.body()
        assert body == b""

        middleware = SecurityMiddleware(app, config=config)

        async def call_next(request: Request) -> Response:
            return Response("Test response with no client", status_code=200)

        middleware_response = await middleware.dispatch(request, call_next)

        assert middleware_response.headers.get("X-Modified") == "True"
        assert middleware_response.status_code == expected_status_code

    else:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            httpx_response = await client.get(request_path, headers=request_headers)

            assert httpx_response.headers.get("X-Modified") == "True"

            assert httpx_response.status_code == expected_status_code

            if expected_status_code >= 400:
                response = await client.get(request_path, headers=request_headers)
                response_json = response.json()
                assert "detail" in response_json
            else:
                assert expected_status_code < 400


@pytest.mark.asyncio
async def test_missing_client_unix_trusted_proxy_rate_limits_forwarded_ip() -> None:
    """
    A connection with no client_host (a Unix domain socket, or a serverless
    adapter that never populates scope["client"]) resolves its identity from
    X-Forwarded-For when "unix" is in trusted_proxies, and that resolved
    identity is what rate limiting is keyed on.
    """
    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        trusted_proxies=("unix",),
        rate_limit=2,
        rate_limit_window=60,
        enable_rate_limiting=True,
    )
    middleware = SecurityMiddleware(app, config=config)

    async def call_next(request: Request) -> Response:
        return Response("ok", status_code=200)

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    def make_scope() -> dict[str, Any]:
        return {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"203.0.113.9")],
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
        }

    statuses = []
    for _ in range(3):
        request = Request(scope=make_scope(), receive=receive)
        response = await middleware.dispatch(request, call_next)
        statuses.append(response.status_code)

    assert statuses == [200, 200, 429]


@pytest.mark.asyncio
async def test_memoryview_response_handling() -> None:
    """Special test for memoryview response handling"""

    test_body_memoryview = memoryview(b"Test Content")

    test_response_memoryview = Response(test_body_memoryview, status_code=400)
    test_response_normal = Response("Normal", status_code=200)
    test_response_bytes = Response(b"Bytes Content", status_code=400)

    assert isinstance(test_response_memoryview.body, memoryview)

    async def custom_modifier(response: Response) -> Response:
        response.headers["X-Modified"] = "True"

        if response.status_code >= 400 and not isinstance(response, JSONResponse):
            content = bytes(response.body).decode()

            return JSONResponse(
                status_code=response.status_code,
                content={"detail": content},
                headers={"X-Modified": "True"},
            )

        return response

    result_memoryview = await custom_modifier(test_response_memoryview)
    assert isinstance(result_memoryview, JSONResponse)
    assert result_memoryview.status_code == 400
    assert result_memoryview.headers.get("X-Modified") == "True"
    result_json = bytes(result_memoryview.body).decode()
    assert "Test Content" in result_json

    result_bytes = await custom_modifier(test_response_bytes)
    assert isinstance(result_bytes, JSONResponse)
    assert result_bytes.status_code == 400
    assert "Bytes Content" in bytes(result_bytes.body).decode()

    result_normal = await custom_modifier(test_response_normal)
    assert result_normal.status_code == 200
    assert not isinstance(result_normal, JSONResponse)
    assert result_normal.headers.get("X-Modified") == "True"


@pytest.mark.asyncio
async def test_cors_configuration() -> None:
    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["X-Custom-Header"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def root() -> dict[str, str]:
        return {"ok": "yes"}

    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    response = await client.options(
        "/",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Custom-Header",
        },
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.headers["access-control-allow-origin"] == "https://example.com"
    assert "GET" in response.headers["access-control-allow-methods"]
    assert response.headers["access-control-max-age"] == "600"


@pytest.mark.asyncio
async def test_cors_configuration_missing_expose_headers() -> None:
    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["X-Custom-Header"],
        cors_allow_credentials=True,
        cors_max_age=600,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def root() -> dict[str, str]:
        return {"ok": "yes"}

    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    response = await client.options(
        "/",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Custom-Header",
        },
    )

    assert "access-control-expose-headers" not in response.headers


@pytest.mark.asyncio
async def test_cloud_ip_blocking() -> None:
    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        block_cloud_providers=frozenset({"AWS", "GCP", "Azure"}),
    )

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with patch.object(
        cloud_handler_for(config, bind=True), "is_cloud_ip", return_value=True
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/", headers={"X-Forwarded-For": "13.59.255.255"}
            )
            assert response.status_code == status.HTTP_403_FORBIDDEN

    with patch.object(
        cloud_handler_for(config, bind=True), "is_cloud_ip", return_value=False
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/", headers={"X-Forwarded-For": "8.8.8.8"})
            assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_cloud_ip_refresh() -> None:
    app = FastAPI()
    config = SecurityConfig(
        block_cloud_providers=frozenset({"AWS", "GCP", "Azure"}),
        enable_penetration_detection=False,
    )
    middleware = SecurityMiddleware(app, config=config)

    with patch.object(
        cloud_handler_for(config, bind=True), "is_cloud_ip", return_value=False
    ) as mock_is_cloud_ip:

        async def receive() -> dict[str, str | bytes]:
            return {"type": "http.request", "body": b"test_body"}

        request = Request(
            scope={
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [(b"x-forwarded-for", b"192.168.1.1")],
                "client": ("192.168.1.1", 12345),
                "query_string": b"",
                "server": ("testserver", 80),
                "scheme": "http",
            },
            receive=receive,
        )

        body = await request.body()
        assert body == b"test_body"

        async def mock_call_next(request: Request) -> Response:
            return Response("OK")

        response = await middleware.dispatch(request, mock_call_next)

        assert mock_is_cloud_ip.called
        assert isinstance(response, Response)
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_cleanup_rate_limits(security_middleware: SecurityMiddleware) -> None:
    await security_middleware.rate_limit_handler.reset()
    assert isinstance(security_middleware.rate_limit_handler.request_timestamps, dict)
    assert len(security_middleware.rate_limit_handler.request_timestamps) == 0


@pytest.mark.asyncio
async def test_excluded_paths() -> None:
    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        exclude_paths=["/health"],
    )

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")
        assert response.status_code == status.HTTP_200_OK


async def _await_scheduled_cloud_refresh(config: SecurityConfig) -> None:
    task = cloud_handler_for(config)._refresh_task
    if task is not None and not task.done():
        await task


@pytest.mark.asyncio
async def test_cloud_ip_blocking_with_refresh() -> None:
    """Test cloud IP blocking with refresh functionality"""
    app = FastAPI()
    config = SecurityConfig(
        block_cloud_providers=frozenset({"AWS", "GCP", "Azure"}),
        enable_redis=False,
        enable_penetration_detection=False,
    )

    cloud_handler_for(config, bind=True)
    middleware = SecurityMiddleware(app, config=config)
    middleware.last_cloud_ip_refresh = int(time.time() - 3700)

    mock_refresh = AsyncMock()
    with (
        patch.object(
            cloud_handler_for(config, bind=True), "refresh_async", mock_refresh
        ),
        patch.object(
            cloud_handler_for(config, bind=True), "is_cloud_ip", return_value=False
        ),
    ):

        async def receive() -> dict[str, str | bytes]:
            return {"type": "http.request", "body": b""}

        request = Request(
            scope={
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [(b"x-forwarded-for", b"192.168.1.1")],
                "client": ("192.168.1.1", 12345),
                "query_string": b"",
                "server": ("testserver", 80),
                "scheme": "http",
            },
            receive=receive,
        )

        body = await request.body()
        assert body == b""

        async def mock_call_next(request: Request) -> Response:
            return Response("OK")

        await middleware.dispatch(request, mock_call_next)
        await _await_scheduled_cloud_refresh(config)
        mock_refresh.assert_called_once()

        mock_refresh.reset_mock()
        await middleware.dispatch(request, mock_call_next)
        mock_refresh.assert_not_called()

    from guard._middleware_state import clear_state_registry

    clear_state_registry()
    config.enable_redis = True
    middleware = SecurityMiddleware(app, config=config)
    middleware.last_cloud_ip_refresh = int(time.time() - 3700)

    mock_refresh_async = AsyncMock()
    with (
        patch.object(
            cloud_handler_for(config, bind=True), "refresh_async", mock_refresh_async
        ),
        patch.object(
            cloud_handler_for(config, bind=True), "is_cloud_ip", return_value=False
        ),
    ):
        await middleware.dispatch(request, mock_call_next)
        await _await_scheduled_cloud_refresh(config)
        assert mock_refresh_async.await_count >= 1


@pytest.mark.asyncio
async def test_refresh_cloud_ips_without_any_cloud() -> None:
    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        block_cloud_providers=None,
    )
    middleware = SecurityMiddleware(app, config=config)
    with (
        patch.object(
            cloud_handler_for(config, bind=True), "refresh_async"
        ) as mock_refresh_async,
        patch.object(cloud_handler_for(config, bind=True), "refresh") as mock_refresh,
    ):
        await middleware.refresh_cloud_ip_ranges()
        mock_refresh_async.assert_not_called()
        mock_refresh.assert_not_called()


@pytest.mark.asyncio
async def test_cors_disabled() -> None:
    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        enable_cors=False,
    )
    middleware = SecurityMiddleware(app, config=config)
    assert middleware._cors_handler is None


@pytest.mark.asyncio
async def test_https_enforcement_with_xforwarded_proto() -> None:
    """Test HTTPS enforcement with X-Forwarded-Proto header."""
    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        enforce_https=True,
        trusted_proxies=("127.0.0.1",),
        trust_x_forwarded_proto=True,
    )

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # With X-Forwarded-Proto: https, should not redirect
        response = await client.get("/", headers={"X-Forwarded-Proto": "https"})
        assert response.status_code == status.HTTP_200_OK

        # Without X-Forwarded-Proto: https, should redirect to HTTPS
        response = await client.get("/", headers={"X-Forwarded-Proto": "http"})
        assert response.status_code == status.HTTP_301_MOVED_PERMANENTLY
        assert response.headers["location"].startswith("https://")

    # Without trust_x_forwarded_proto, should always redirect
    config.trust_x_forwarded_proto = False
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"X-Forwarded-Proto": "https"})
        assert response.status_code == status.HTTP_301_MOVED_PERMANENTLY


@pytest.mark.asyncio
async def test_cleanup_expired_request_times() -> None:
    """Test cleanup of expired request times"""
    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        rate_limit=2,
        rate_limit_window=1,
    )
    middleware = SecurityMiddleware(app, config=config)

    handler = middleware.rate_limit_handler
    await handler.reset()

    assert len(handler.request_timestamps) == 0

    current_time = time.time()
    # Test data
    handler.request_timestamps["ip1"].append(current_time)
    handler.request_timestamps["ip1"].append(current_time)
    handler.request_timestamps["ip2"].append(current_time)

    assert len(handler.request_timestamps["ip1"]) == 2
    assert len(handler.request_timestamps["ip2"]) == 1
    assert len(handler.request_timestamps) == 2

    # Reset and verify cleared
    await handler.reset()
    assert len(handler.request_timestamps) == 0


@pytest.mark.asyncio
async def test_penetration_detection_disabled() -> None:
    """Test when penetration detection is disabled"""
    app = FastAPI()
    config = SecurityConfig(enable_penetration_detection=False)

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    @app.get("/wp-admin")
    async def admin_page() -> dict[str, str]:
        return {"message": "Admin"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/wp-admin")
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_cloud_ip_blocking_with_logging() -> None:
    """Test cloud IP blocking with logging functionality"""
    app = FastAPI()
    config = SecurityConfig(
        block_cloud_providers=frozenset({"AWS", "GCP", "Azure"}),
        whitelist=(),  # IP passes via patched check_ip_access
        blacklist=(),  # Empty blacklist
        trusted_proxies=("13.59.255.255",),  # Trust the IP as proxy
        enable_penetration_detection=False,
    )
    middleware = SecurityMiddleware(app, config=config)

    call_next_executed = False

    async def mock_call_next(request: Request) -> Response:
        nonlocal call_next_executed
        call_next_executed = True
        return Response("OK")

    with (
        patch.object(
            cloud_handler_for(config, bind=True), "is_cloud_ip", return_value=True
        ),
        patch(
            "guard_core.core.checks.implementations.cloud_provider.log_activity"
        ) as mock_log,
        patch(
            "guard_core.core.checks.implementations.ip_security.check_ip_access",
            new_callable=AsyncMock,
            return_value=IpAccessResult(allowed=True, reason=""),
        ),
    ):

        async def receive() -> dict[str, str | bytes]:
            return {"type": "http.request", "body": b""}

        request = Request(
            scope={
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [(b"x-forwarded-for", b"13.59.255.255")],
                "client": ("13.59.255.255", 12345),
                "query_string": b"",
                "server": ("testserver", 80),
                "scheme": "http",
            },
            receive=receive,
        )

        body = await request.body()
        assert body == b""

        response = await middleware.dispatch(request, mock_call_next)

        assert_log_activity_called_with(
            mock_log,
            log_type="suspicious",
            reason="Blocked cloud provider IP: 13.59.255.255",
            level="WARNING",
            passive_mode=False,
            check_name="cloud_provider",
            muted_check_logs=set(),
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert not call_next_executed, (
            "call_next should not be executed when IP is blocked"
        )

    with (
        patch.object(
            cloud_handler_for(config, bind=True), "is_cloud_ip", return_value=False
        ),
        patch(
            "guard_core.core.checks.implementations.ip_security.check_ip_access",
            new_callable=AsyncMock,
            return_value=IpAccessResult(allowed=True, reason=""),
        ),
    ):

        async def receive2() -> dict[str, str | bytes]:
            return {"type": "http.request", "body": b""}

        request = Request(
            scope={
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [(b"x-forwarded-for", b"192.168.1.1")],
                "client": ("192.168.1.1", 12345),
                "query_string": b"",
                "server": ("testserver", 80),
                "scheme": "http",
            },
            receive=receive2,
        )

        body = await request.body()
        assert body == b""

        response = await middleware.dispatch(request, mock_call_next)

        assert response.status_code == status.HTTP_200_OK
        assert call_next_executed, "call_next should be executed for allowed IPs"


@pytest.mark.asyncio
async def test_redis_initialization(security_config_redis: SecurityConfig) -> None:
    """Test Redis initialization in SecurityMiddleware"""
    app = FastAPI()

    security_config_redis.block_cloud_providers = frozenset({"AWS"})
    security_config_redis.lazy_init = False

    middleware = SecurityMiddleware(app, config=security_config_redis)

    # Mock external handlers - patch at module level where they're imported
    with (
        patch.object(middleware.redis_handler, "initialize") as redis_init,
        patch.object(
            cloud_handler_for(security_config_redis, bind=True), "initialize_redis"
        ) as cloud_init,
        patch.object(
            ip_ban_manager_for(security_config_redis, bind=True), "initialize_redis"
        ) as ipban_init,
        patch.object(IPInfoManager, "initialize_redis") as ipinfo_init,
        patch.object(
            sus_patterns_manager_for(security_config_redis, bind=True),
            "initialize_redis",
        ) as sus_init,
        patch.object(
            middleware.handler_initializer.rate_limit_handler, "initialize_redis"
        ) as rate_init,
    ):
        await middleware.initialize()

        # Verify Redis handler initialization
        redis_init.assert_awaited_once()

        # Verify component initializations with Redis
        cloud_init.assert_awaited_once_with(middleware.redis_handler, {"AWS"}, ttl=3600)
        ipban_init.assert_awaited_once_with(middleware.redis_handler)
        ipinfo_init.assert_awaited_once_with(middleware.redis_handler)
        sus_init.assert_awaited_once_with(middleware.redis_handler)
        rate_init.assert_awaited_once_with(middleware.redis_handler)


@pytest.mark.asyncio
async def test_redis_initialization_without_country_rules_or_cloud(
    security_config_redis: SecurityConfig,
) -> None:
    """Test Redis initialization in SecurityMiddleware"""
    app = FastAPI()

    security_config_redis.blocked_countries = frozenset()

    middleware = SecurityMiddleware(app, config=security_config_redis)

    # Mock external handlers - patch at module level where they're imported
    with (
        patch.object(middleware.redis_handler, "initialize") as redis_init,
        patch.object(
            cloud_handler_for(security_config_redis, bind=True), "initialize_redis"
        ) as cloud_init,
        patch.object(
            ip_ban_manager_for(security_config_redis, bind=True), "initialize_redis"
        ) as ipban_init,
        patch.object(IPInfoManager, "initialize_redis") as ipinfo_init,
        patch.object(
            sus_patterns_manager_for(security_config_redis, bind=True),
            "initialize_redis",
        ) as sus_init,
        patch.object(
            middleware.handler_initializer.rate_limit_handler, "initialize_redis"
        ) as rate_init,
    ):
        await middleware.initialize()
        lazy_init = middleware.handler_initializer._lazy_init_task
        if lazy_init is not None:
            await lazy_init

        # Verify Redis handler initialization
        redis_init.assert_awaited_once()

        # Verify component initializations with Redis
        cloud_init.assert_not_called()
        ipban_init.assert_awaited_once_with(middleware.redis_handler)
        ipinfo_init.assert_awaited_once_with(middleware.redis_handler)
        sus_init.assert_awaited_once_with(middleware.redis_handler)
        rate_init.assert_awaited_once_with(middleware.redis_handler)


@pytest.mark.asyncio
async def test_redis_disabled(security_config: SecurityConfig) -> None:
    """Test middleware behavior when Redis is disabled"""
    app = FastAPI()
    security_config.enable_redis = False
    middleware = SecurityMiddleware(app, config=security_config)

    assert middleware.redis_handler is None
    await middleware.initialize()

    assert middleware.rate_limit_handler is not None
    await middleware.rate_limit_handler.reset()


@pytest.mark.asyncio
async def test_request_without_client(security_config: SecurityConfig) -> None:
    """Test handling of request without client info"""
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=security_config)

    call_next_called = False

    async def mock_call_next(request: Request) -> Response:
        nonlocal call_next_called
        call_next_called = True
        return Response("OK")

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    response = await middleware.dispatch(request, mock_call_next)

    assert not call_next_called
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_rate_limiting_disabled() -> None:
    """Test when rate limiting is disabled"""
    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        enable_rate_limiting=False,
    )

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        for _ in range(10):
            response = await client.get("/")
            assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_rate_limiting_with_redis(security_config_redis: SecurityConfig) -> None:
    """Test rate limiting with Redis"""

    app = FastAPI()
    security_config_redis.rate_limit = 2
    security_config_redis.rate_limit_window = 10
    security_config_redis.whitelist = ()
    security_config_redis.blocked_countries = frozenset()

    cleanup = redis_handler(security_config_redis)
    await cleanup.initialize()
    await cleanup.delete_pattern("rate_limit:rate:*")
    await cleanup.close()

    app.add_middleware(SecurityMiddleware, config=security_config_redis)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/")
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        middleware = _serving_middleware(app)
        await middleware.rate_limit_handler.reset()
        await middleware.rate_limit_handler.initialize_redis(middleware.redis_handler)

        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_rate_limit_reset_with_redis_errors(
    security_config_redis: SecurityConfig,
) -> None:
    """Test rate limit reset handling Redis errors"""

    security_config_redis.rate_limit = 2
    security_config_redis.enable_rate_limiting = True

    handler = redis_handler(security_config_redis)

    rate_handler = rate_limit_handler(security_config_redis)
    await rate_handler.initialize_redis(handler)

    async def mock_keys(*args: Any) -> None:
        raise Exception("Redis keys error")

    with (
        patch.object(rate_handler.redis_handler, "keys", mock_keys),
        patch.object(rate_handler.redis_handler, "delete_pattern", mock_keys),
        patch.object(logging.Logger, "error") as mock_logger,
    ):
        await rate_handler.reset()

        # Verify error was logged
        mock_logger.assert_called_once()
        args = mock_logger.call_args[0]
        assert "Failed to reset Redis rate limits" in args[0]


@pytest.mark.asyncio
async def test_passive_mode_penetration_detection() -> None:
    """Test penetration detection in passive mode"""
    app = FastAPI()
    config = SecurityConfig(
        passive_mode=True,
        whitelist=(),
    )
    middleware = SecurityMiddleware(app, config=config)

    call_next_called = False

    async def mock_call_next(request: Request) -> Response:
        nonlocal call_next_called
        call_next_called = True
        return Response("OK")

    with (
        patch(
            "guard_core.core.checks.implementations.suspicious_activity.get_cached_detection_result",
            new_callable=AsyncMock,
            return_value=DetectionResult(
                is_threat=True, trigger_info="SQL injection attempt"
            ),
        ) as mock_detect,
        patch(
            "guard_core.core.checks.implementations.suspicious_activity.log_activity"
        ) as mock_log,
        patch(
            "guard_core.utils.detect_penetration_attempt",
            return_value=DetectionResult(
                is_threat=True, trigger_info="SQL injection attempt"
            ),
        ),
    ):

        async def receive() -> dict[str, str | bytes]:
            return {"type": "http.request", "body": b"' OR 1=1; --"}

        request = Request(
            scope={
                "type": "http",
                "method": "GET",
                "path": "/login",
                "headers": [(b"user-agent", b"test-agent")],
                "client": ("192.168.1.1", 12345),
                "query_string": b"",
                "server": ("testserver", 80),
                "scheme": "http",
            },
            receive=receive,
        )

        body = await request.body()
        assert b"' OR 1=1; --" in body

        response = await middleware.dispatch(request, mock_call_next)

        assert response.status_code == status.HTTP_200_OK
        assert call_next_called, "call_next should be called in passive mode"

        assert mock_detect.called, "get_cached_detection_result should be called"

        assert_log_activity_called_with(
            mock_log,
            log_type="suspicious",
            reason="Suspicious activity detected: 192.168.1.1",
            passive_mode=True,
            trigger_info="SQL injection attempt",
            level="WARNING",
            check_name="suspicious_activity",
            muted_check_logs=set(),
        )


@pytest.mark.asyncio
async def test_sliding_window_rate_limiting() -> None:
    """Test that sliding window rate limiting works correctly"""
    app = FastAPI()
    config = SecurityConfig(
        enable_penetration_detection=False,
        rate_limit=3,
        rate_limit_window=1,
        enable_rate_limiting=True,
    )

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    handler = rate_limit_handler(config)
    await handler.reset()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # First 3 requests should be allowed
        for _ in range(3):
            response = await client.get("/")
            assert response.status_code == status.HTTP_200_OK

        # 4th request should be rate limited
        response = await client.get("/")
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        # Wait for window to slide plus a little extra to be safe
        await asyncio.sleep(1.5)

        # After 1.5 seconds, the rate limit should reset
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_rate_limiter_deque_cleanup(security_config: SecurityConfig) -> None:
    """Test cleanup of old requests from the deque"""
    handler = rate_limit_handler(security_config)
    await handler.reset()

    current_time = time.time()
    window_start = current_time - security_config.rate_limit_window

    client_ip = "192.168.1.1"

    old_queue = handler.request_timestamps[client_ip]
    old_queue.append(window_start - 0.5)
    old_queue.append(window_start - 0.7)
    old_queue.append(window_start - 0.2)

    assert len(old_queue) == 3
    assert all(ts < window_start for ts in old_queue)

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "client": (client_ip, 12345),
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    guard_request = StarletteGuardRequest(request)

    async def create_error_response(
        status_code: int, message: str
    ) -> StarletteGuardResponse:
        return StarletteGuardResponse(Response(message, status_code=status_code))

    response = await create_error_response(429, "Test message")
    assert response.status_code == 429
    assert response.body == b"Test message"

    result = await handler.check_rate_limit(
        guard_request, client_ip, create_error_response
    )

    assert result is None

    assert len(handler.request_timestamps[client_ip]) == 1

    handler.request_timestamps[client_ip].clear()
    handler.request_timestamps[client_ip].append(window_start - 10)
    handler.request_timestamps[client_ip].append(window_start + 0.5)

    result = await handler.check_rate_limit(
        guard_request, client_ip, create_error_response
    )

    assert result is None

    assert len(handler.request_timestamps[client_ip]) == 2
    assert all(ts >= window_start for ts in handler.request_timestamps[client_ip])


def _serving_middleware(app: FastAPI) -> SecurityMiddleware:
    node: Any = app.middleware_stack
    while not isinstance(node, SecurityMiddleware):
        node = node.app
    return node


def _loopback_guard_request() -> StarletteGuardRequest:
    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "client": ("192.168.1.1", 12345),
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
        },
        receive=receive,
    )
    return StarletteGuardRequest(request)


async def _redis_rate_limiter(config: SecurityConfig) -> Any:
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=config)
    handler = middleware.rate_limit_handler
    redis = redis_handler(config)
    await redis.initialize()
    await handler.initialize_redis(redis)
    return handler, redis


async def _create_error_response(
    status_code: int, message: str
) -> StarletteGuardResponse:
    return StarletteGuardResponse(Response(message, status_code=status_code))


async def _three_checks(handler: Any) -> list[Any]:
    guard_request = _loopback_guard_request()
    return [
        await handler.check_rate_limit(
            guard_request, "192.168.1.1", _create_error_response
        )
        for _ in range(3)
    ]


@pytest.mark.asyncio
async def test_lua_script_execution(security_config_redis: SecurityConfig) -> None:
    """The Lua script is loaded and used for rate limiting with Redis"""
    config = security_config_redis
    config.rate_limit = 2
    config.rate_limit_window = 60
    config.enable_rate_limiting = True

    handler, redis = await _redis_rate_limiter(config)
    try:
        assert handler.rate_limit_script_sha is not None
        async with redis.get_connection() as conn:
            before = (await conn.info("commandstats")).get("cmdstat_evalsha", {})
            results = await _three_checks(handler)
            after = (await conn.info("commandstats")).get("cmdstat_evalsha", {})

        assert results[0] is None
        assert results[1] is None
        assert results[2] is not None
        assert results[2].status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert after.get("calls", 0) - before.get("calls", 0) >= 3
    finally:
        await redis.delete_pattern("rate_limit:rate:*")
        await redis.close()


@pytest.mark.asyncio
async def test_fallback_to_pipeline(security_config_redis: SecurityConfig) -> None:
    """Rate limiting still works on Redis when the Lua script is not loaded"""
    config = security_config_redis
    config.rate_limit = 2
    config.rate_limit_window = 60
    config.enable_rate_limiting = True

    handler, redis = await _redis_rate_limiter(config)
    try:
        handler.rate_limit_script_sha = None
        async with redis.get_connection() as conn:
            before = (await conn.info("commandstats")).get("cmdstat_evalsha", {})
            results = await _three_checks(handler)
            after = (await conn.info("commandstats")).get("cmdstat_evalsha", {})

        assert results[0] is None
        assert results[1] is None
        assert results[2] is not None
        assert results[2].status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert results[2].body == b"Too many requests"
        assert after.get("calls", 0) == before.get("calls", 0)
    finally:
        await redis.delete_pattern("rate_limit:rate:*")
        await redis.close()


@pytest.mark.asyncio
async def test_rate_limiter_redis_errors(security_config_redis: SecurityConfig) -> None:
    """Test Redis error handling in rate limit check"""
    config = security_config_redis
    config.rate_limit = 2
    config.rate_limit_window = 1
    config.enable_rate_limiting = True

    handler, redis = await _redis_rate_limiter(config)

    guard_request = _loopback_guard_request()
    create_error_response = _create_error_response

    error_response = await create_error_response(429, "Rate limited")
    assert error_response.status_code == 429
    assert error_response.body == b"Rate limited"

    with (
        patch.object(handler.redis_handler, "get_connection") as mock_get_connection,
        patch.object(logging.Logger, "error") as mock_error,
    ):
        mock_conn = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(
            side_effect=RedisError("Redis connection error")
        )
        mock_get_connection.return_value = mock_conn

        handler.rate_limit_script_sha = "test_script_sha"

        with pytest.raises(GuardRedisError):
            await handler.check_rate_limit(
                guard_request, "192.168.1.1", create_error_response
            )

        mock_error.assert_called_once()
        assert "Redis rate limiting error" in mock_error.call_args[0][0]

        mock_error.reset_mock()
        config.redis_fail_open = True

        result = await handler.check_rate_limit(
            guard_request, "192.168.1.1", create_error_response
        )

        assert result is None
        mock_error.assert_not_called()

        config.redis_fail_open = False

    with (
        patch.object(handler.redis_handler, "get_connection") as mock_get_connection,
        patch.object(logging.Logger, "error") as mock_error,
    ):
        mock_conn = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(side_effect=Exception("Unexpected error"))
        mock_get_connection.return_value = mock_conn

        with pytest.raises(GuardRedisError):
            await handler.check_rate_limit(
                guard_request, "192.168.1.1", create_error_response
            )

        mock_error.assert_called_once()
        assert "Unexpected error in rate limiting" in mock_error.call_args[0][0]

        mock_error.reset_mock()
        config.redis_fail_open = True

        result = await handler.check_rate_limit(
            guard_request, "192.168.1.1", create_error_response
        )

        assert result is None
        mock_error.assert_not_called()

    await redis.close()


@pytest.mark.asyncio
async def test_rate_limiter_init_redis_exception(
    security_config_redis: SecurityConfig,
) -> None:
    """Test exception handling during Redis script loading"""
    handler = rate_limit_handler(security_config_redis)

    mock_redis = Mock()
    mock_cm = AsyncMock()
    mock_conn = AsyncMock()
    mock_conn.script_load = AsyncMock(side_effect=Exception("Script load failed"))
    mock_cm.__aenter__.return_value = mock_conn
    mock_redis.get_connection.return_value = mock_cm

    mock_logger = Mock()
    handler.logger = mock_logger

    await handler.initialize_redis(mock_redis)

    mock_logger.error.assert_called_once()
    error_msg = mock_logger.error.call_args[0][0]
    assert "Failed to load rate limiting Lua script: Script load failed" == error_msg


@pytest.mark.asyncio
async def test_ipv6_rate_limiting(
    security_config_redis: SecurityConfig, clean_rate_limiter: None
) -> None:
    """
    Test the rate limiting functionality
    of the SecurityMiddleware with IPv6 addresses.
    """
    app = FastAPI()
    config = security_config_redis
    config.rate_limit = 2
    config.rate_limit_window = 1
    config.enable_rate_limiting = True
    config.trusted_proxies = ("127.0.0.1",)
    config.whitelist = ()
    config.blocked_countries = frozenset()
    config.enable_penetration_detection = False

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        middleware = _serving_middleware(app)
        await middleware.rate_limit_handler.reset()
        await middleware.rate_limit_handler.initialize_redis(middleware.redis_handler)

        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_ipv6_whitelist_blacklist(security_config_redis: SecurityConfig) -> None:
    """
    Test the IPv6 whitelist/blacklist
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()
    config = security_config_redis
    config.whitelist = ("::1", "2001:db8::1")
    config.blacklist = ("2001:db8::dead:beef",)
    config.enable_penetration_detection = False
    config.trusted_proxies = ("127.0.0.1", "::1")

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # IPv6 loopback
        response = await client.get("/", headers={"X-Forwarded-For": "::1"})
        assert response.status_code == status.HTTP_200_OK

        # Whitelisted IPv6 address
        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == status.HTTP_200_OK

        # Blacklisted IPv6 address
        response = await client.get(
            "/", headers={"X-Forwarded-For": "2001:db8::dead:beef"}
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # Non-whitelisted IPv6 address (block)
        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::2"})
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_ipv6_cidr_whitelist_blacklist(
    security_config_redis: SecurityConfig,
) -> None:
    """
    Test IPv6 CIDR notation in whitelist/blacklist.
    """
    app = FastAPI()
    config = security_config_redis
    config.whitelist = ("2001:db8::/32",)
    config.blacklist = ("2001:db8:dead::/48",)
    config.enable_penetration_detection = False
    config.trusted_proxies = ("127.0.0.1", "::1")

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # IPv6 address in whitelisted CIDR
        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8:1::1"})
        assert response.status_code == status.HTTP_200_OK

        # IPv6 in both a whitelist CIDR and the blacklist: the blacklist denies
        response = await client.get(
            "/", headers={"X-Forwarded-For": "2001:db8:dead::beef"}
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # IPv6 address outside whitelisted CIDR
        response = await client.get("/", headers={"X-Forwarded-For": "2001:db9::1"})
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_mixed_ipv4_ipv6_handling(security_config_redis: SecurityConfig) -> None:
    """
    Test handling of mixed IPv4 and IPv6 addresses in configuration.
    """
    app = FastAPI()
    config = security_config_redis
    config.whitelist = ("127.0.0.1", "::1", "192.168.1.0/24", "2001:db8::/32")
    config.blacklist = ("192.168.1.100", "2001:db8:dead::beef")
    config.enable_penetration_detection = False
    config.trusted_proxies = ("127.0.0.1", "::1")

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # IPv4 addresses
        response = await client.get("/", headers={"X-Forwarded-For": "127.0.0.1"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.50"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.100"})
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # IPv6 addresses
        response = await client.get("/", headers={"X-Forwarded-For": "::1"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get(
            "/", headers={"X-Forwarded-For": "2001:db8:dead::beef"}
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_real_ipv6_connection(
    security_config_redis: SecurityConfig, clean_rate_limiter: None
) -> None:
    """
    Test with a real IPv6 client connection using direct Request objects.
    This validates that the middleware can handle actual IPv6 client IPs,
    not just IPv6 addresses in proxy headers.
    """
    config = security_config_redis
    config.rate_limit = 3
    config.rate_limit_window = 10
    config.enable_rate_limiting = True
    config.whitelist = ()
    config.blacklist = ("2001:db8::2",)
    config.blocked_countries = frozenset()
    config.enable_penetration_detection = False

    middleware = SecurityMiddleware(app=Mock(), config=config)

    async def mock_call_next(request: Request) -> Response:
        return Response("OK", status_code=200)

    async def receive() -> dict[str, str | bytes | bool]:
        return {"type": "http.request", "body": b"", "more_body": False}

    # IPv6 client (allowed, not blacklisted)
    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "client": ("2001:db8::1", 12345),
            "server": ("testserver", 80),
            "scheme": "http",
        },
        receive=receive,
    )

    response = await middleware.dispatch(request, mock_call_next)
    assert response.status_code == 200

    response = await middleware.dispatch(request, mock_call_next)
    assert response.status_code == 200

    response = await middleware.dispatch(request, mock_call_next)
    assert response.status_code == 200

    response = await middleware.dispatch(request, mock_call_next)
    assert response.status_code == 429

    # Blacklisted IPv6 client
    request_blocked = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "client": ("2001:db8::2", 12345),  # NOTE: Blacklisted IPv6 client
            "server": ("testserver", 80),
            "scheme": "http",
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    response = await middleware.dispatch(request_blocked, mock_call_next)
    assert response.status_code == 403


async def test_emergency_mode_passive(security_config: SecurityConfig) -> None:
    """Test emergency mode in passive mode."""
    app = FastAPI()
    security_config.emergency_mode = True
    security_config.passive_mode = True
    security_config.trusted_proxies = ("127.0.0.1",)

    @app.get("/test")
    async def test_endpoint() -> dict[str, str]:
        return {"message": "ok"}

    app.add_middleware(SecurityMiddleware, config=security_config)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Should pass in passive mode
        response = await client.get("/test", headers={"X-Forwarded-For": "8.8.8.8"})
        assert response.status_code == 200


async def test_guard_response_factory_property() -> None:
    from guard.adapters import StarletteResponseFactory

    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)
    assert isinstance(middleware.guard_response_factory, StarletteResponseFactory)


async def test_security_headers_not_configured() -> None:
    app = FastAPI()
    config = SecurityConfig(security_headers=None)
    SecurityMiddleware(app, config=config)


async def test_security_headers_disabled() -> None:
    app = FastAPI()
    config = SecurityConfig(security_headers={"enabled": False})
    SecurityMiddleware(app, config=config)


async def test_agent_initialization_success() -> None:
    app = FastAPI()
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-key-long-enough-for-validation",
    )
    middleware = SecurityMiddleware(app, config=config)
    assert middleware.agent_handler is not None


async def test_agent_initialization_import_error() -> None:
    import builtins
    import sys

    app = FastAPI()
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-key-long-enough-for-validation",
    )
    fake_agent_config = config.to_agent_config()

    original_import = builtins.__import__
    saved_modules = {
        k: sys.modules.pop(k) for k in list(sys.modules) if k.startswith("guard_agent")
    }

    def mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "guard_agent":
            raise ImportError("No module named 'guard_agent'")
        return original_import(name, *args, **kwargs)

    try:
        with (
            patch.object(
                SecurityConfig, "to_agent_config", return_value=fake_agent_config
            ),
            patch("builtins.__import__", side_effect=mock_import),
        ):
            middleware = SecurityMiddleware(app, config=config)
            assert middleware.agent_handler is None
    finally:
        sys.modules.update(saved_modules)


async def test_agent_initialization_exception() -> None:
    app = FastAPI()
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-key",
    )
    with patch(
        "guard_agent.GuardAgentHandler", side_effect=RuntimeError("init failed")
    ):
        middleware = SecurityMiddleware(app, config=config)

    assert middleware.agent_handler is None
    assert middleware.agent_degraded is True


async def test_agent_initialization_invalid_config() -> None:
    app = FastAPI()
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-key",
    )
    with patch.object(SecurityConfig, "to_agent_config", return_value=None):
        middleware = SecurityMiddleware(app, config=config)

    assert middleware.agent_handler is None
    assert middleware.agent_degraded is True


async def test_resolve_route_no_app_routes() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/nonexistent",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
        "app": app,
    }
    from starlette.requests import Request as StarletteRequest

    request = StarletteRequest(scope)
    result = middleware._resolve_route(request)
    assert result is None


async def test_resolve_route_returns_already_populated_scope_route() -> None:
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=SecurityConfig())

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/whatever",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
        "app": app,
        "route": "already-resolved",
    }
    from starlette.requests import Request as StarletteRequest

    request = StarletteRequest(scope)
    assert middleware._resolve_route(request) == "already-resolved"


def _http_scope(app: Starlette, method: str, path: str) -> dict[str, Any]:
    return {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
        "app": app,
    }


async def test_resolve_route_matches_path_parameter_route() -> None:
    app = FastAPI()

    @app.get("/items/{item_id}")
    async def get_item(item_id: str) -> dict[str, str]:
        return {"item_id": item_id}

    middleware = SecurityMiddleware(app, config=SecurityConfig())

    from starlette.requests import Request as StarletteRequest

    request = StarletteRequest(_http_scope(app, "GET", "/items/42"))
    route = middleware._resolve_route(request)
    assert isinstance(route, Route)
    assert route.endpoint is get_item


async def test_resolve_route_attaches_decorator_config_to_parameterised_route() -> None:
    from guard import SecurityDecorator

    app = FastAPI()
    config = SecurityConfig()
    guard = SecurityDecorator(config)

    @app.post("/items/{item_id}/action")
    @guard.rate_limit(requests=5, window=60)
    async def act(item_id: str) -> dict[str, bool]:
        return {"ok": True}

    app.state.guard_decorator = guard
    middleware = SecurityMiddleware(app, config=config)

    from starlette.requests import Request as StarletteRequest

    request = StarletteRequest(_http_scope(app, "POST", "/items/7/action"))
    route = middleware._resolve_route(request)
    assert isinstance(route, Route)
    assert hasattr(route.endpoint, "_guard_route_id")
    route_config = guard.get_route_config(route.endpoint._guard_route_id)
    assert route_config is not None
    assert route_config.rate_limit == 5


async def test_resolve_route_matches_included_router_route() -> None:
    from fastapi import APIRouter

    router = APIRouter()

    @router.post("/api/things")
    async def create_thing() -> dict[str, bool]:
        return {"ok": True}

    app = FastAPI()
    app.include_router(router)
    middleware = SecurityMiddleware(app, config=SecurityConfig())

    from starlette.requests import Request as StarletteRequest

    request = StarletteRequest(_http_scope(app, "POST", "/api/things"))
    route = middleware._resolve_route(request)
    assert isinstance(route, Route)
    assert route.endpoint is create_thing


async def test_resolve_route_ignores_method_mismatch_on_parameter_route() -> None:
    app = FastAPI()

    @app.get("/items/{item_id}")
    async def get_item(item_id: str) -> dict[str, str]:
        return {"item_id": item_id}

    middleware = SecurityMiddleware(app, config=SecurityConfig())

    from starlette.requests import Request as StarletteRequest

    request = StarletteRequest(_http_scope(app, "DELETE", "/items/42"))
    assert middleware._resolve_route(request) is None


async def test_resolve_route_matches_prefixed_included_router_route() -> None:
    from fastapi import APIRouter

    router = APIRouter(prefix="/api/mcp")

    @router.post("/servers/{server_id}")
    async def reconnect(server_id: str) -> dict[str, str | bool]:
        return {"ok": True, "server_id": server_id}

    app = FastAPI()
    app.include_router(router)
    middleware = SecurityMiddleware(app, config=SecurityConfig())

    from starlette.requests import Request as StarletteRequest

    request = StarletteRequest(_http_scope(app, "POST", "/api/mcp/servers/9"))
    route = middleware._resolve_route(request)
    assert isinstance(route, Route)
    assert route.endpoint is reconnect


async def test_route_match_handles_missing_and_raising_matches() -> None:
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=SecurityConfig())

    class _NoMatches:
        pass

    class _RaisingMatches:
        def matches(self, scope: Any) -> Any:
            raise RuntimeError("boom")

    assert middleware._route_match(_NoMatches(), {}) == (Match.NONE, {})
    assert middleware._route_match(_RaisingMatches(), {}) == (Match.NONE, {})


async def test_match_route_stops_on_self_nesting_router() -> None:
    from starlette.routing import Match

    app = FastAPI()
    middleware = SecurityMiddleware(app, config=SecurityConfig())

    class _SelfNestingRouter:
        def matches(self, scope: Any) -> Any:
            return Match.FULL, {}

        @property
        def routes(self) -> Any:
            return [self]

    matched = middleware._match_route(
        [_SelfNestingRouter()], {"type": "http"}, set(), (Match.FULL,)
    )
    assert next(matched, None) is None


async def test_match_route_visits_duplicate_mount_subtrees_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route

    async def endpoint(request: Any) -> JSONResponse:
        return JSONResponse({})

    depth = 20
    apps = [Starlette(routes=[Route("/end", endpoint)]) for _ in range(depth + 1)]
    for i in range(depth):
        for _ in range(2):
            apps[i].router.routes.append(Mount("/x", app=apps[i + 1]))

    root = apps[0]
    middleware = SecurityMiddleware(root, config=SecurityConfig())

    calls = 0
    original = middleware._route_match

    def counting_match(route: Any, scope: Any) -> tuple[Match, Any]:
        nonlocal calls
        calls += 1
        return original(route, scope)

    monkeypatch.setattr(middleware, "_route_match", counting_match)

    from starlette.requests import Request as StarletteRequest

    request = StarletteRequest(_http_scope(root, "GET", "/x" * depth + "/nope"))
    assert middleware._resolve_route(request) is None
    assert calls < 500


async def test_resolve_route_matches_deeply_nested_mounted_apps() -> None:
    depth = 12
    apps = [FastAPI() for _ in range(depth + 1)]

    @apps[-1].get("/secret")
    async def secret() -> dict[str, bool]:
        return {"secret": True}

    for i in range(depth - 1, -1, -1):
        apps[i].mount(f"/m{i}", apps[i + 1])

    root = apps[0]
    middleware = SecurityMiddleware(root, config=SecurityConfig())

    from starlette.requests import Request as StarletteRequest

    path = "".join(f"/m{i}" for i in range(depth)) + "/secret"
    request = StarletteRequest(_http_scope(root, "GET", path))
    route = middleware._resolve_route(request)
    assert isinstance(route, Route)
    assert route.endpoint is secret


async def test_resolve_route_matches_deeply_nested_prefixed_routers() -> None:
    from fastapi import APIRouter

    depth = 12
    routers = [APIRouter(prefix=f"/r{i}") for i in range(depth)]

    @routers[-1].get("/secret")
    async def secret() -> dict[str, bool]:
        return {"secret": True}

    for i in range(depth - 2, -1, -1):
        routers[i].include_router(routers[i + 1])

    app = FastAPI()
    app.include_router(routers[0])
    middleware = SecurityMiddleware(app, config=SecurityConfig())

    from starlette.requests import Request as StarletteRequest

    path = "".join(f"/r{i}" for i in range(depth)) + "/secret"
    request = StarletteRequest(_http_scope(app, "GET", path))
    route = middleware._resolve_route(request)
    assert isinstance(route, Route)
    assert route.endpoint is secret


async def test_resolve_route_matches_mount_inside_prefixed_included_router() -> None:
    from fastapi import APIRouter

    sub = FastAPI()

    @sub.get("/secret")
    async def secret() -> dict[str, bool]:
        return {"secret": True}

    router = APIRouter()
    router.mount("/sub", sub)
    app = FastAPI()
    app.include_router(router, prefix="/api")
    middleware = SecurityMiddleware(app, config=SecurityConfig())

    from starlette.requests import Request as StarletteRequest

    request = StarletteRequest(_http_scope(app, "GET", "/api/sub/secret"))
    route = middleware._resolve_route(request)
    assert isinstance(route, Route)
    assert route.endpoint is secret


async def test_resolve_route_matches_router_included_twice_at_different_prefixes() -> (
    None
):
    from fastapi import APIRouter

    shared = APIRouter()

    @shared.get("/end")
    async def end() -> dict[str, bool]:
        return {"ok": True}

    app = FastAPI()
    app.include_router(shared, prefix="/v1")
    app.include_router(shared, prefix="/v2")
    middleware = SecurityMiddleware(app, config=SecurityConfig())

    from starlette.requests import Request as StarletteRequest

    for prefix in ("/v1", "/v2"):
        request = StarletteRequest(_http_scope(app, "GET", f"{prefix}/end"))
        route = middleware._resolve_route(request)
        assert isinstance(route, Route)
        assert route.endpoint is end


async def test_process_response_wires_global_behavioral_rules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    from starlette.requests import Request as StarletteRequest

    request = StarletteRequest(_http_scope(app, "GET", "/"))
    response = Response(content="ok", status_code=200)
    process_response = AsyncMock(return_value=StarletteGuardResponse(response))
    monkeypatch.setattr(
        middleware.response_factory, "process_response", process_response
    )

    await middleware._process_response(request, response, 0.01, None)

    awaited = process_response.await_args
    assert awaited is not None
    kwargs = awaited.kwargs
    assert (
        kwargs["process_global_behavioral_rules"]
        == middleware.behavioral_processor.process_global_return_rules
    )


async def test_populate_guard_state_marks_only_unresolved_routes() -> None:
    app = FastAPI()

    @app.get("/known")
    async def known() -> dict[str, bool]:
        return {"ok": True}

    middleware = SecurityMiddleware(app, config=SecurityConfig())

    from starlette.requests import Request as StarletteRequest

    unmatched = StarletteRequest(_http_scope(app, "GET", "/missing"))
    unmatched_guard = StarletteGuardRequest(unmatched)
    middleware._populate_guard_state(unmatched_guard, unmatched)
    assert unmatched_guard.state.guard_route_unresolved is True

    matched = StarletteRequest(_http_scope(app, "GET", "/known"))
    matched_guard = StarletteGuardRequest(matched)
    middleware._populate_guard_state(matched_guard, matched)
    assert not hasattr(matched_guard.state, "guard_route_unresolved")


async def test_populate_guard_state_accepts_mount_to_routeless_app() -> None:
    from starlette.responses import PlainTextResponse

    async def raw_app(scope: Any, receive: Any, send: Any) -> None:
        await PlainTextResponse("raw")(scope, receive, send)

    app = FastAPI()
    app.mount("/raw", raw_app)
    middleware = SecurityMiddleware(app, config=SecurityConfig())

    from starlette.requests import Request as StarletteRequest

    request = StarletteRequest(_http_scope(app, "GET", "/raw/thing"))
    guard_request = StarletteGuardRequest(request)
    middleware._populate_guard_state(guard_request, request)

    assert not hasattr(guard_request.state, "guard_route_unresolved")
    assert not hasattr(guard_request.state, "guard_route_id")


async def test_populate_guard_state_skips_endpoint_id_without_qualname() -> None:
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=SecurityConfig())

    class _CallableEndpoint:
        pass

    scope = _http_scope(app, "GET", "/whatever")
    scope["route"] = SimpleNamespace(endpoint=_CallableEndpoint())

    from starlette.requests import Request as StarletteRequest

    request = StarletteRequest(scope)
    guard_request = StarletteGuardRequest(request)
    middleware._populate_guard_state(guard_request, request)

    assert not hasattr(guard_request.state, "guard_endpoint_id")


async def test_require_auth_enforced_on_deeply_nested_mounted_route() -> None:
    from guard import SecurityDecorator

    depth = 12
    config = SecurityConfig(
        enable_penetration_detection=False,
        enforce_https=False,
        enable_redis=False,
        enable_rate_limiting=False,
    )
    guard = SecurityDecorator(config)
    apps = [FastAPI() for _ in range(depth + 1)]

    @guard.require_auth(type="bearer")
    @apps[-1].get("/secret")
    async def secret() -> dict[str, bool]:
        return {"secret": True}

    for i in range(depth - 1, -1, -1):
        apps[i].mount(f"/m{i}", apps[i + 1])

    root = apps[0]
    root.add_middleware(SecurityMiddleware, config=config)
    root.state.guard_decorator = guard

    path = "".join(f"/m{i}" for i in range(depth)) + "/secret"
    async with AsyncClient(
        transport=ASGITransport(app=root), base_url="http://test"
    ) as client:
        response = await client.get(path)

    assert response.status_code == 401


async def test_agent_stats_returns_disabled_when_agent_handler_unset() -> None:
    app = FastAPI()
    config = SecurityConfig(enable_agent=False)
    middleware = SecurityMiddleware(app, config=config)
    assert middleware.agent_handler is None
    assert middleware.agent_stats == {"enabled": False, "degraded": False}


async def test_agent_stats_returns_enabled_with_agent_handler_stats() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    fake_handler = Mock()
    fake_handler.get_stats.return_value = {
        "buffer_stats": {"events_dropped": 0, "metrics_dropped": 0},
        "transport_stats": {"circuit_breaker_state": "CLOSED"},
    }
    middleware.agent_handler = fake_handler

    stats = middleware.agent_stats
    assert stats["enabled"] is True
    assert stats["buffer_stats"] == {"events_dropped": 0, "metrics_dropped": 0}
    assert stats["transport_stats"] == {"circuit_breaker_state": "CLOSED"}
    fake_handler.get_stats.assert_called_once()


async def test_agent_stats_reflects_live_drop_counter_increments() -> None:
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    fake_handler = Mock()
    fake_handler.get_stats.return_value = {
        "buffer_stats": {"events_dropped": 0, "metrics_dropped": 0},
        "transport_stats": {"circuit_breaker_state": "CLOSED"},
    }
    middleware.agent_handler = fake_handler

    first = json.loads(json.dumps(middleware.agent_stats))
    assert first["buffer_stats"]["events_dropped"] == 0

    fake_handler.get_stats.return_value = {
        "buffer_stats": {"events_dropped": 7, "metrics_dropped": 3},
        "transport_stats": {"circuit_breaker_state": "OPEN"},
    }

    second = json.loads(json.dumps(middleware.agent_stats))
    assert second["buffer_stats"]["events_dropped"] == 7
    assert second["buffer_stats"]["metrics_dropped"] == 3
    assert second["transport_stats"]["circuit_breaker_state"] == "OPEN"
    assert fake_handler.get_stats.call_count == 2
