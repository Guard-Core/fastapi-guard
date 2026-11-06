import socket
from collections.abc import Iterator
from unittest.mock import patch

import pytest

from tests import network_guard


def test_non_loopback_connect_is_refused_and_recorded() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(network_guard.NetworkAccessError):
            sock.connect(("203.0.113.7", 443))
    assert len(network_guard.drain()) == 1


def test_non_loopback_connect_ex_is_refused_and_recorded() -> None:
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
        with pytest.raises(network_guard.NetworkAccessError):
            sock.connect_ex(("2001:db8::1", 443, 0, 0))
    assert len(network_guard.drain()) == 1


def test_guard_survives_patch_stopall() -> None:
    patch.stopall()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(network_guard.NetworkAccessError):
            sock.connect(("203.0.113.7", 443))
    assert len(network_guard.drain()) == 1


def test_loopback_connect_is_allowed() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect(server.getsockname())
    assert network_guard.drain() == []


@pytest.mark.parametrize(
    ("family", "address", "allowed"),
    [
        (socket.AF_INET6, ("::1", 80, 0, 0), True),
        (socket.AF_INET6, ("::ffff:127.0.0.1", 80, 0, 0), True),
        (socket.AF_INET, ("localhost", 80), True),
        (socket.AF_UNIX, "/tmp/any.sock", True),
        (socket.AF_INET, ("143.204.55.127", 443), False),
        (socket.AF_INET, ("example.com", 443), False),
        (socket.AF_INET6, ("2001:db8::1", 443, 0, 0), False),
    ],
)
def test_is_allowed_decision(
    family: int, address: tuple[object, ...] | str | bytes, allowed: bool
) -> None:
    assert network_guard.is_allowed(family, address) is allowed


@pytest.fixture
def configured_endpoints() -> Iterator[None]:
    saved = network_guard._configured_endpoints
    yield
    network_guard._configured_endpoints = saved


def _resolving_to(monkeypatch: pytest.MonkeyPatch, address: str) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, **_: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))
        ],
    )


@pytest.mark.usefixtures("configured_endpoints")
def test_configured_redis_host_and_port_are_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _resolving_to(monkeypatch, "192.0.2.10")
    network_guard.configure("redis://cache.internal:6478")

    assert network_guard.is_allowed(socket.AF_INET, ("192.0.2.10", 6478))
    assert network_guard.is_allowed(socket.AF_INET, ("cache.internal", 6478))


@pytest.mark.usefixtures("configured_endpoints")
def test_configured_redis_host_on_another_port_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _resolving_to(monkeypatch, "192.0.2.10")
    network_guard.configure("redis://cache.internal:6478")

    assert not network_guard.is_allowed(socket.AF_INET, ("192.0.2.10", 6379))
    assert not network_guard.is_allowed(socket.AF_INET, ("cache.internal", 80))


@pytest.mark.usefixtures("configured_endpoints")
def test_another_host_on_the_configured_port_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _resolving_to(monkeypatch, "192.0.2.10")
    network_guard.configure("redis://cache.internal:6478")

    assert not network_guard.is_allowed(socket.AF_INET, ("192.0.2.11", 6478))


@pytest.mark.usefixtures("configured_endpoints")
def test_loopback_stays_allowed_with_a_configured_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _resolving_to(monkeypatch, "192.0.2.10")
    network_guard.configure("redis://cache.internal:6478")

    assert network_guard.is_allowed(socket.AF_INET, ("127.0.0.1", 1))


@pytest.mark.usefixtures("configured_endpoints")
def test_an_unresolvable_redis_host_allows_only_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_: object, **__: object) -> None:
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    network_guard.configure("redis://nowhere.invalid:6478")

    assert not network_guard.is_allowed(socket.AF_INET, ("nowhere.invalid", 6478))
    assert not network_guard.is_allowed(socket.AF_INET, ("192.0.2.10", 6478))
    assert network_guard.is_allowed(socket.AF_INET, ("::1", 6478, 0, 0))
