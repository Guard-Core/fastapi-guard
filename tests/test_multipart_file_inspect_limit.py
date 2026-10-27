from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from guard import SecurityConfig
from guard.middleware import SecurityMiddleware

BODY_LIMIT = 262144
DEFAULT_FILE_LIMIT = SecurityConfig().detection_max_file_inspect_bytes
PAST_THE_LIMIT_PADDING = BODY_LIMIT + 1024
RAISED_FILE_LIMIT = 1_000_000
BOUNDARY = "wp251boundary"
_PAYLOAD = "1' UNION SELECT password FROM users--"
_HEADERS = {"X-Forwarded-For": "203.0.113.50"}
_MULTIPART = {**_HEADERS, "Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}
_JSON = {**_HEADERS, "Content-Type": "application/json"}


def _multipart_body() -> bytes:
    pad = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="pad"\r\n\r\n'
        f"{'A' * PAST_THE_LIMIT_PADDING}\r\n"
    )
    comment = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="comment"\r\n\r\n'
        f"{_PAYLOAD}\r\n--{BOUNDARY}--\r\n"
    )
    return (pad + comment).encode()


def _json_body() -> bytes:
    return (
        '{"pad": "' + "A" * PAST_THE_LIMIT_PADDING + '", "comment": "' + _PAYLOAD + '"}'
    ).encode()


def _chunked(payload: bytes, chunk_size: int = 8192) -> AsyncIterator[bytes]:
    async def chunks() -> AsyncIterator[bytes]:
        for start in range(0, len(payload), chunk_size):
            yield payload[start : start + chunk_size]

    return chunks()


def _client(file_limit: int) -> AsyncClient:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        trusted_proxies=("127.0.0.1",),
        detection_max_file_inspect_bytes=file_limit,
    )
    app = FastAPI()

    @app.post("/upload")
    async def upload() -> dict[str, str]:
        return {"ok": "upload"}

    app.add_middleware(SecurityMiddleware, config=config)
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.parametrize("chunked", [False, True])
async def test_multipart_past_the_body_limit_is_scanned_under_a_raised_file_limit(
    chunked: bool,
) -> None:
    body = _multipart_body()
    async with _client(RAISED_FILE_LIMIT) as client:
        response = await client.post(
            "/upload", content=_chunked(body) if chunked else body, headers=_MULTIPART
        )

    assert response.status_code == 400
    assert "Suspicious activity detected" in response.text


@pytest.mark.parametrize("chunked", [False, True])
async def test_a_multipart_body_past_the_default_file_limit_is_refused_not_passed(
    chunked: bool,
) -> None:
    body = _multipart_body()
    async with _client(DEFAULT_FILE_LIMIT) as client:
        response = await client.post(
            "/upload", content=_chunked(body) if chunked else body, headers=_MULTIPART
        )

    assert response.status_code == 400
    assert "Suspicious activity detected" not in response.text


@pytest.mark.parametrize("chunked", [False, True])
async def test_a_json_body_of_the_same_size_stays_refused_under_a_raised_file_limit(
    chunked: bool,
) -> None:
    body = _json_body()
    async with _client(RAISED_FILE_LIMIT) as client:
        response = await client.post(
            "/upload", content=_chunked(body) if chunked else body, headers=_JSON
        )

    assert response.status_code == 400
    assert "Suspicious activity detected" not in response.text
