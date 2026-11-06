import ipaddress
import os
import socket
import traceback
from urllib.parse import urlparse

import pytest

_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain"})
_STACK_FRAMES = 12
_DEFAULT_REDIS_URL = "redis://localhost:6379"
_DEFAULT_REDIS_PORT = 6379


class NetworkAccessError(OSError):
    pass


_violations: list[str] = []
_configured_endpoints: frozenset[tuple[str, int]] = frozenset()
_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex


def _host_is_loopback(host: str) -> bool:
    if host in _LOOPBACK_NAMES:
        return True
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped.is_loopback
    return address.is_loopback


def _normalized(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host.split("%", 1)[0]))
    except ValueError:
        return host


def resolve_endpoints(url: str) -> frozenset[tuple[str, int]]:
    parsed = urlparse(url)
    if not parsed.hostname:
        return frozenset()
    port = parsed.port or _DEFAULT_REDIS_PORT
    try:
        infos = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except OSError:
        return frozenset()
    return frozenset(
        {(_normalized(str(info[4][0])), port) for info in infos}
        | {(_normalized(parsed.hostname), port)}
    )


def configure(redis_url: str) -> None:
    global _configured_endpoints
    _configured_endpoints = resolve_endpoints(redis_url)


_Address = tuple[object, ...] | str | bytes


def is_allowed(family: int, address: _Address) -> bool:
    if family == socket.AF_UNIX:
        return True
    if isinstance(address, tuple) and len(address) >= 2 and isinstance(address[0], str):
        host, port = address[0], address[1]
        return _host_is_loopback(host) or (_normalized(host), port) in (
            _configured_endpoints
        )
    return False


def _record(address: _Address) -> NetworkAccessError:
    frames = "".join(traceback.format_stack(limit=_STACK_FRAMES + 2)[:-2])
    _violations.append(f"connect to {address!r}\n{frames}")
    return NetworkAccessError(f"tests must not reach the network: {address!r}")


def _guarded_connect(self: socket.socket, address: _Address) -> None:
    if not is_allowed(self.family, address):
        raise _record(address)
    _real_connect(self, address)


def _guarded_connect_ex(self: socket.socket, address: _Address) -> int:
    if not is_allowed(self.family, address):
        raise _record(address)
    return _real_connect_ex(self, address)


_installer = pytest.MonkeyPatch()


def install() -> None:
    configure(os.getenv("REDIS_URL") or _DEFAULT_REDIS_URL)
    # Not unittest.mock.patch: a test that calls patch.stopall() would lift it.
    _installer.setattr(socket.socket, "connect", _guarded_connect)
    _installer.setattr(socket.socket, "connect_ex", _guarded_connect_ex)


def reset() -> None:
    _violations.clear()


def drain() -> list[str]:
    drained = list(_violations)
    _violations.clear()
    return drained
