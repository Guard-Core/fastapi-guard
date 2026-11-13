"""The per-request route match is cached (bounded, keyed on the request's route
text and Host) and dropped when the route table changes: a route added after the
first request, at the top or under a Mount, is resolved on its next request."""

from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
from fastapi import FastAPI
from guard_core.models import SecurityConfig
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from guard import SecurityDecorator
from guard.asgi import PureASGISecurityMiddleware
from guard.lifespan import _built_security_middleware
from guard.middleware import SecurityMiddleware

CLASSES = pytest.mark.parametrize(
    "middleware_class",
    [SecurityMiddleware, PureASGISecurityMiddleware],
    ids=["classic", "pure"],
)
WALLED = ["10.1.1.1"]


class _Matches:
    calls = 0


@pytest.fixture
def matches_per_request(monkeypatch: pytest.MonkeyPatch) -> type[_Matches]:
    original = Route.matches

    def counting(self: Route, scope: Any) -> Any:
        _Matches.calls += 1
        return original(self, scope)

    monkeypatch.setattr(Route, "matches", counting)
    _Matches.calls = 0
    return _Matches


def _walled(decorator: SecurityDecorator) -> Callable[..., Any]:
    @decorator.require_ip(whitelist=WALLED)
    async def walled(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    return walled


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        enable_rate_limiting=False,
        enable_penetration_detection=False,
        ban_on_hostile_signals=False,
    )


def _app(middleware_class: Any) -> tuple[FastAPI, SecurityDecorator]:
    config = _config()
    app = FastAPI()
    decorator = SecurityDecorator(config)
    app.state.guard_decorator = decorator
    app.add_api_route("/a/{x}", _walled(decorator), methods=["GET"])
    for index in range(20):

        async def plain() -> dict[str, bool]:
            return {"plain": True}

        app.add_api_route(f"/p{index}", plain, methods=["GET"])
    app.add_middleware(middleware_class, config=config)
    return app, decorator


@pytest.fixture
async def client_of() -> AsyncIterator[Callable[[Any], AsyncClient]]:
    clients: list[AsyncClient] = []

    def make(app: Any) -> AsyncClient:
        client = AsyncClient(
            transport=ASGITransport(app=app, client=("127.0.0.1", 50000)),
            base_url="http://testserver",
        )
        clients.append(client)
        return client

    yield make
    for client in clients:
        await client.aclose()


async def _cost(client: AsyncClient, path: str, counter: type[_Matches]) -> int:
    counter.calls = 0
    await client.get(path)
    return counter.calls


@CLASSES
async def test_a_repeated_request_does_not_walk_the_route_table_again(
    middleware_class: Any,
    client_of: Callable[[Any], AsyncClient],
    matches_per_request: type[_Matches],
) -> None:
    app, _ = _app(middleware_class)
    client = client_of(app)
    await client.get("/p19")

    first = await _cost(client, "/p19", matches_per_request)
    second = await _cost(client, "/p19", matches_per_request)

    assert second < first


@CLASSES
async def test_the_cache_keeps_the_bound_and_evicts_the_oldest(
    middleware_class: Any,
    client_of: Callable[[Any], AsyncClient],
    matches_per_request: type[_Matches],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("guard.middleware._ROUTE_MATCH_CACHE_SIZE", 2, raising=False)
    app, _ = _app(middleware_class)
    client = client_of(app)
    await client.get("/a/warm")
    for name in ("one", "two", "three"):
        await client.get(f"/a/{name}")

    newest = await _cost(client, "/a/three", matches_per_request)
    evicted = await _cost(client, "/a/one", matches_per_request)

    assert newest < evicted


@CLASSES
async def test_a_route_added_at_the_top_after_a_miss_is_resolved(
    middleware_class: Any,
    client_of: Callable[[Any], AsyncClient],
) -> None:
    app, decorator = _app(middleware_class)
    client = client_of(app)
    assert (await client.get("/late")).status_code == 404
    assert (await client.get("/late")).status_code == 404

    app.add_api_route("/late", _walled(decorator), methods=["GET"])

    assert (await client.get("/late")).status_code == 403


@CLASSES
async def test_a_route_added_under_a_mount_after_a_miss_is_resolved(
    middleware_class: Any,
    client_of: Callable[[Any], AsyncClient],
) -> None:
    app, decorator = _app(middleware_class)
    sub = Starlette()
    app.mount("/sub", sub)
    client = client_of(app)
    assert (await client.get("/sub/late")).status_code == 404
    assert (await client.get("/sub/late")).status_code == 404

    sub.router.routes.append(Route("/late", _walled(decorator)))

    assert (await client.get("/sub/late")).status_code == 403


@CLASSES
async def test_every_cached_match_still_applies_its_routes_decorator(
    middleware_class: Any,
    client_of: Callable[[Any], AsyncClient],
) -> None:
    app, _ = _app(middleware_class)
    client = client_of(app)

    statuses = [(await client.get(f"/a/{i % 3}")).status_code for i in range(9)]

    assert statuses == [403] * 9


@CLASSES
async def test_attacker_sized_paths_are_keyed_by_a_bounded_hash(
    middleware_class: Any,
    client_of: Callable[[Any], AsyncClient],
) -> None:
    app, _ = _app(middleware_class)
    client = client_of(app)
    for index in range(4):
        await client.get(f"/{'z' * 5000}{index}")

    engine = _built_security_middleware(app)
    keys = list(getattr(engine, "_route_matches", {}))

    assert keys
    assert all(
        len(part) <= 256 for key in keys for part in key if isinstance(part, str)
    )
