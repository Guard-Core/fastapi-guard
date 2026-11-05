import socket
from collections.abc import Generator
from urllib.parse import urlparse

import pytest
import redis

from tests.conftest import REDIS_PREFIX, REDIS_URL
from tests.redis_isolation import _is_forbidden_default_port

OUTSIDE_KEY = "wp35a:outside:sentinel"
INSIDE_KEY = f"{REDIS_PREFIX}wp35a:inside:leftover"


@pytest.fixture(scope="module")
def keys_written_before_every_test_in_this_module() -> Generator[None, None, None]:
    client = redis.Redis.from_url(REDIS_URL)
    client.set(OUTSIDE_KEY, "1")
    client.set(INSIDE_KEY, "1")
    yield
    client.delete(OUTSIDE_KEY, INSIDE_KEY)
    client.close()


@pytest.mark.usefixtures("keys_written_before_every_test_in_this_module")
def test_cleanup_removes_a_key_the_suite_wrote_under_its_prefix() -> None:
    client = redis.Redis.from_url(REDIS_URL)
    try:
        assert client.exists(INSIDE_KEY) == 0
    finally:
        client.close()


@pytest.mark.usefixtures("keys_written_before_every_test_in_this_module")
def test_a_key_outside_the_suite_prefix_survives_the_cleanup() -> None:
    client = redis.Redis.from_url(REDIS_URL)
    try:
        assert client.exists(OUTSIDE_KEY) == 1
    finally:
        client.close()


def test_a_connection_to_port_6379_is_refused_and_recorded(
    refused_redis_connections: list[tuple[object, ...]],
) -> None:
    if (urlparse(REDIS_URL).port or 6379) == 6379:
        # The suite's own Redis is on 6379, so the guard stands down for that port.
        assert not _is_forbidden_default_port(("localhost", 6379))
        return
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(("localhost", 6379), timeout=1)
    assert refused_redis_connections
    refused_redis_connections.clear()
