import os
import socket
from typing import Any
from urllib.parse import urlparse

import pytest
import redis
from guard_core.models import SecurityConfig

REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"
REDIS_PREFIX = os.getenv("REDIS_PREFIX") or "test:fastapi_guard:"

DEFAULT_REDIS_PORT = 6379
LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")

refused_connections: list[tuple[Any, ...]] = []


def _is_forbidden_default_port(address: object) -> bool:
    if (urlparse(REDIS_URL).port or DEFAULT_REDIS_PORT) == DEFAULT_REDIS_PORT:
        return False
    return (
        isinstance(address, tuple)
        and len(address) >= 2
        and address[1] == DEFAULT_REDIS_PORT
        and address[0] in LOOPBACK_HOSTS
    )


def refuse_connections_to_the_default_redis_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def connect(self: socket.socket, address: Any) -> None:
        if _is_forbidden_default_port(address):
            refused_connections.append(address)
            raise ConnectionRefusedError(
                f"test tried port {DEFAULT_REDIS_PORT}, REDIS_URL is {REDIS_URL}"
            )
        original_connect(self, address)

    def connect_ex(self: socket.socket, address: Any) -> int:
        if _is_forbidden_default_port(address):
            refused_connections.append(address)
            return 111
        return original_connect_ex(self, address)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)


def point_security_config_defaults_at_the_test_redis() -> None:
    fields = SecurityConfig.model_fields
    fields["redis_url"].default = REDIS_URL
    fields["redis_prefix"].default = REDIS_PREFIX
    SecurityConfig.model_rebuild(force=True)


def delete_every_key_under_the_suite_prefix() -> None:
    client = redis.Redis.from_url(REDIS_URL)
    try:
        pending = list(client.scan_iter(match=f"{REDIS_PREFIX}*", count=500))
        if pending:
            client.unlink(*pending)
    finally:
        client.close()


def suite_redis_prefix(tag: str) -> str:
    return f"{REDIS_PREFIX}{tag}:"
