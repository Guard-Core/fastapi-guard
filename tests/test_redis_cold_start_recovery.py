import asyncio
import socket
import threading
import time
import uuid
from collections.abc import Iterator
from urllib.parse import urlparse

import pytest
import redis as redis_sync
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from guard import SecurityConfig, SecurityMiddleware
from tests.redis_isolation import REDIS_URL


class RedisForwarder:
    """A local port that forwards to the real Redis only while it is on. Off, nothing
    listens on it, so a client gets connection refused like a Redis that is down."""

    def __init__(self) -> None:
        target = urlparse(REDIS_URL)
        self._target = (target.hostname or "127.0.0.1", target.port or 6379)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = int(probe.getsockname()[1])
        self._listener: socket.socket | None = None
        self._open: list[socket.socket] = []
        self._lock = threading.Lock()

    @property
    def url(self) -> str:
        return urlparse(REDIS_URL)._replace(netloc=f"127.0.0.1:{self.port}").geturl()

    def on(self) -> None:
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self.port))
        listener.listen()
        self._listener = listener
        threading.Thread(target=self._accept, args=(listener,), daemon=True).start()

    def off(self) -> None:
        listener, self._listener = self._listener, None
        if listener is not None:
            listener.close()
        with self._lock:
            sockets, self._open = self._open, []
        for sock in sockets:
            self._close(sock)

    def _accept(self, listener: socket.socket) -> None:
        while True:
            try:
                client, _ = listener.accept()
            except OSError:
                return
            upstream = socket.create_connection(self._target)
            with self._lock:
                self._open.extend((client, upstream))
            for source, sink in ((client, upstream), (upstream, client)):
                threading.Thread(
                    target=self._pipe, args=(source, sink), daemon=True
                ).start()

    @staticmethod
    def _close(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

    def _pipe(self, source: socket.socket, sink: socket.socket) -> None:
        try:
            while data := source.recv(65536):
                sink.sendall(data)
        except OSError:
            pass
        finally:
            self._close(source)
            self._close(sink)


@pytest.fixture
def forwarder() -> Iterator[RedisForwarder]:
    forward = RedisForwarder()
    yield forward
    forward.off()


@pytest.fixture
def prefix() -> Iterator[str]:
    own = f"wp450:fg:{uuid.uuid4().hex}:"
    yield own
    client = redis_sync.Redis.from_url(REDIS_URL)
    for key in client.scan_iter(f"{own}*"):
        client.delete(key)
    client.close()


def keys_under(prefix: str) -> int:
    client = redis_sync.Redis.from_url(REDIS_URL)
    count = sum(1 for _ in client.scan_iter(f"{prefix}*"))
    client.close()
    return count


def app_for(
    url: str, prefix: str, *, fail_open: bool, enable_redis: bool = True
) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        SecurityMiddleware,
        config=SecurityConfig(
            enable_redis=enable_redis,
            redis_url=url,
            redis_prefix=prefix,
            redis_fail_open=fail_open,
            enable_rate_limiting=True,
            rate_limit=1000,
            rate_limit_window=60,
        ),
    )

    @app.get("/h")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    return app


async def test_fail_open_app_started_while_redis_was_down_uses_redis_once_back(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = app_for(forwarder.url, prefix, fail_open=True)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.get("/h")).status_code == 200
        assert keys_under(prefix) == 0

        forwarder.on()
        await asyncio.sleep(0.3)
        for _ in range(3):
            assert (await client.get("/h")).status_code == 200

    assert keys_under(prefix) > 0


async def test_fail_closed_app_serves_within_half_a_second_of_a_redis_blip(
    forwarder: RedisForwarder, prefix: str
) -> None:
    app = app_for(forwarder.url, prefix, fail_open=False)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.get("/h")).status_code == 503
        await asyncio.sleep(0.1)
        forwarder.on()
        restored = time.monotonic()
        first_200 = None
        while time.monotonic() - restored < 2.0:
            if (await client.get("/h")).status_code == 200:
                first_200 = time.monotonic() - restored
                break
            await asyncio.sleep(0.05)
        assert first_200 is not None and first_200 < 0.5
        assert (await client.get("/h")).status_code == 200
    assert keys_under(prefix) > 0
