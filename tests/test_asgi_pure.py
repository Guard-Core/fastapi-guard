"""Tests for the pure-ASGI security middleware variant."""

import asyncio
import itertools

from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from guard import PureASGISecurityMiddleware, SecurityConfig

# Rate limiting and ban state in guard-core are process-wide, so every test
# drives its own TEST-NET client IP to stay hermetic.
_IP = itertools.count(1)


def _unique_ip() -> str:
    n = next(_IP)
    return f"198.51.{n // 250}.{(n % 250) + 1}"


def _build_app(config: SecurityConfig, *, with_echo: bool = False) -> FastAPI:
    app = FastAPI()
    app.add_middleware(PureASGISecurityMiddleware, config=config)

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    @app.get("/health")
    async def health():
        return {"ok": "health"}

    if with_echo:

        @app.post("/echo")
        async def echo(request: Request):
            return {"received": await request.json()}

    return app


def _run(scenario, client_ip, config, with_echo=False):
    async def runner():
        transport = ASGITransport(
            app=_build_app(config, with_echo=with_echo), client=(client_ip, 50000)
        )
        async with AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await scenario(client)

    return asyncio.run(runner())


def _base_config(**overrides):
    kwargs = {
        # In-memory state unless a Redis URL is configured: never implicitly
        # depend on a Redis server being reachable at localhost.
        "enable_redis": False,
        "exclude_paths": ["/health"],
    }
    kwargs.update(overrides)
    return SecurityConfig(**kwargs)


def test_blocked_ip_is_rejected():
    blocked = _unique_ip()
    config = _base_config(blacklist=(blocked,))

    async def scenario(client):
        response = await client.get("/ping")
        assert response.status_code == 403

    _run(scenario, blocked, config)


def test_rate_limit_returns_429():
    client_ip = _unique_ip()
    config = _base_config(rate_limit=2, rate_limit_window=60)

    async def scenario(client):
        assert (await client.get("/ping")).status_code == 200
        assert (await client.get("/ping")).status_code == 200
        assert (await client.get("/ping")).status_code == 429

    _run(scenario, client_ip, config)


def test_passive_mode_never_blocks():
    blocked = _unique_ip()
    config = _base_config(passive_mode=True, blacklist=(blocked,))

    async def scenario(client):
        response = await client.get("/ping")
        assert response.status_code == 200

    _run(scenario, blocked, config)


def test_ip_lists_enforced_on_excluded_paths():
    blocked = _unique_ip()
    config = _base_config(blacklist=(blocked,))

    async def scenario(client):
        response = await client.get("/health")
        assert response.status_code == 403

    _run(scenario, blocked, config)


def test_rate_limiting_applies_on_excluded_paths():
    client_ip = _unique_ip()
    config = _base_config(rate_limit=1, rate_limit_window=60)

    async def scenario(client):
        codes = [(await client.get("/health")).status_code for _ in range(3)]
        assert codes == [200, 429, 429]

    _run(scenario, client_ip, config)


def test_security_headers_injected_on_response():
    client_ip = _unique_ip()
    config = _base_config(
        security_headers={
            "enabled": True,
            "frame_options": "SAMEORIGIN",
            "content_type_options": "nosniff",
        }
    )

    async def scenario(client):
        response = await client.get("/ping")
        assert response.status_code == 200
        assert response.headers["x-frame-options"] == "SAMEORIGIN"
        assert response.headers["x-content-type-options"] == "nosniff"

    _run(scenario, client_ip, config)


def test_body_reaches_downstream_after_guard_reads_it():
    client_ip = _unique_ip()
    config = _base_config()

    async def scenario(client):
        response = await client.post(
            "/echo",
            json={"message": "hello guard"},
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 200
        assert response.json() == {"received": {"message": "hello guard"}}

    # inline Body import keeps the echo signature local to this test
    _run(scenario, client_ip, config, with_echo=True)


def test_non_http_scopes_pass_through():
    calls: list[str] = []

    class ProbeApp:
        async def __call__(self, scope, receive, send):
            calls.append(scope["type"])

    middleware = PureASGISecurityMiddleware(ProbeApp(), config=_base_config())
    asyncio.run(middleware.__call__({"type": "lifespan"}, lambda: None, lambda _: None))
    assert calls == ["lifespan"]
