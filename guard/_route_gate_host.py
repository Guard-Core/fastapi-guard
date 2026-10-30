from contextvars import ContextVar, Token

_host: ContextVar[str] = ContextVar("guard_route_gate_host", default="")


def hold_route_gate_host(host: str) -> Token[str]:
    """Make this request's Host the one the route-gate helpers match against.

    The engine asks the adapter about a path (`resolve_route`, `allowed_methods`,
    `static_file_exists`) without a request, so a Starlette `Host(...)` route is
    only found when the request's Host is in force while the engine asks.
    """
    return _host.set(host)


def release_route_gate_host(token: Token[str]) -> None:
    _host.reset(token)


def route_gate_host() -> str:
    return _host.get()
