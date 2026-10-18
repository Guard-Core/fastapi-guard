"""Tests for the pure-ASGI security middleware variant."""

import asyncio
import itertools
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
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


def test_rate_limiting_on_excluded_paths_follows_the_engine():
    client_ip = _unique_ip()
    config = _base_config(rate_limit=1, rate_limit_window=60)
    expected = (
        [200, 429, 429] if RateLimitCheck.enforced_on_excluded_paths else [200] * 3
    )

    async def scenario(client):
        codes = [(await client.get("/health")).status_code for _ in range(3)]
        assert codes == expected

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


def test_bypassed_route_skips_checks():
    from guard import SecurityDecorator

    blocked = "203.0.113.9"
    config = _base_config(blacklist=(blocked,))
    app = FastAPI()
    app.add_middleware(PureASGISecurityMiddleware, config=config)
    decorator = SecurityDecorator(config)
    app.state.guard_decorator = decorator

    @decorator.bypass(["all"])
    @app.get("/bypassed")
    async def bypassed():
        return {"ok": True}

    async def runner():
        transport = ASGITransport(app=app, client=(blocked, 50000))
        async with AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return (await client.get("/bypassed")).status_code

    assert asyncio.run(runner()) == 200


def test_unknown_client_fails_secure():
    config = _base_config()
    app = FastAPI()
    app.add_middleware(PureASGISecurityMiddleware, config=config)

    captured: dict[str, Any] = {}

    async def send(message):
        captured[message["type"]] = message

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "path": "/ping",
        "raw_path": b"/ping",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver")],
        # no "client" key: guard cannot determine the source address
    }
    asyncio.run(app(scope, receive, send))
    assert captured["http.response.start"]["status"] == 403


def test_null_app_raises_if_called():
    async def exercise():
        app = FastAPI()
        middleware = PureASGISecurityMiddleware(app, config=_base_config())
        await middleware._engine.app({"type": "http"}, lambda: None, lambda _: None)

    try:
        asyncio.run(exercise())
        raised = False
    except RuntimeError:
        raised = True
    assert raised


def test_redis_unavailable_returns_503():
    from guard_core.exceptions import GuardRedisError

    client_ip = _unique_ip()
    config = _base_config()
    app = FastAPI()
    middleware = PureASGISecurityMiddleware(app, config=config)

    async def raise_redis_error(request):
        raise GuardRedisError(503, "connection refused")

    middleware._engine._ensure_initialized = raise_redis_error

    async def runner():
        transport = ASGITransport(app=middleware, client=(client_ip, 50000))
        async with AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return (await client.get("/ping")).status_code

    assert asyncio.run(runner()) == 503


def test_cors_preflight_and_response_headers():
    client_ip = _unique_ip()
    config = _base_config(
        enable_cors=True,
        cors_allow_origins=["http://good.origin"],
        cors_allow_methods=["GET"],
        cors_allow_headers=["*"],
    )
    app = FastAPI()
    app.add_middleware(PureASGISecurityMiddleware, config=config)

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    async def runner():
        transport = ASGITransport(app=app, client=(client_ip, 50000))
        async with AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            preflight = await client.options(
                "/ping",
                headers={
                    "Origin": "http://good.origin",
                    "Access-Control-Request-Method": "GET",
                },
            )
            response = await client.get(
                "/ping", headers={"Origin": "http://good.origin"}
            )
        return preflight, response

    preflight, response = asyncio.run(runner())
    assert preflight.status_code == 200
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == ("http://good.origin")


def test_blocked_response_carries_cors_headers():
    blocked = _unique_ip()
    config = _base_config(
        enable_cors=True,
        cors_allow_origins=["http://good.origin"],
        blacklist=(blocked,),
    )
    app = FastAPI()
    app.add_middleware(PureASGISecurityMiddleware, config=config)

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    async def runner():
        transport = ASGITransport(app=app, client=(blocked, 50000))
        async with AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.get("/ping", headers={"Origin": "http://good.origin"})

    response = asyncio.run(runner())
    assert response.status_code == 403
    assert response.headers.get("access-control-allow-origin") == ("http://good.origin")


def test_behavioral_usage_rules_processed():
    from guard import SecurityDecorator

    client_ip = _unique_ip()
    config = _base_config()
    app = FastAPI()
    app.add_middleware(PureASGISecurityMiddleware, config=config)
    decorator = SecurityDecorator(config)
    app.state.guard_decorator = decorator

    @decorator.usage_monitor(max_calls=100, window=3600, action="ban")
    @app.get("/monitored")
    async def monitored():
        return {"ok": True}

    async def runner():
        transport = ASGITransport(app=app, client=(client_ip, 50000))
        async with AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return (await client.get("/monitored")).status_code

    assert asyncio.run(runner()) == 200


def test_body_caching_receive_replays_then_yields_inner():
    from guard.asgi import _BodyCachingReceive

    served = [
        {"type": "http.request", "body": b"chunk-one", "more_body": True},
        {"type": "http.request", "body": b"chunk-two", "more_body": False},
    ]
    inner_calls: list[dict] = []

    async def inner():
        message = served.pop(0) if served else {"type": "http.disconnect"}
        inner_calls.append(message)
        return message

    receive = _BodyCachingReceive(inner)

    async def drive():
        first = await receive()
        second = await receive()
        replayed = receive.replay()
        replayed_messages = [await replayed() for _ in range(2)]
        third = await replayed()
        return first, second, replayed_messages, third

    first, second, replayed_messages, third = asyncio.run(drive())
    assert first["body"] == b"chunk-one"
    assert second["body"] == b"chunk-two"
    assert [m["body"] for m in replayed_messages] == [b"chunk-one", b"chunk-two"]
    assert third["type"] == "http.disconnect"
    # inner served the two body chunks, then the post-body disconnect wait
    assert [m["body"] for m in inner_calls[:2]] == [b"chunk-one", b"chunk-two"]
    assert inner_calls[-1]["type"] == "http.disconnect"


def test_chunked_body_is_cached_and_replayed():
    client_ip = _unique_ip()
    config = _base_config(enable_penetration_detection=False)
    app = FastAPI()
    app.add_middleware(PureASGISecurityMiddleware, config=config)
    bodies: list[bytes] = []

    @app.post("/upload")
    async def upload(request: Request):
        async for chunk in request.stream():
            bodies.append(chunk)
        return {"size": len(b"".join(bodies))}

    served = [
        {"type": "http.request", "body": b"part-one-", "more_body": True},
        {"type": "http.request", "body": b"part-two", "more_body": False},
    ]

    async def receive():
        return served.pop(0)

    captured: dict[str, Any] = {}

    async def send(message):
        if message["type"] == "http.response.start":
            captured["status"] = message["status"]

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "path": "/upload",
        "raw_path": b"/upload",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver"), (b"content-type", b"text/plain")],
        "client": (client_ip, 50000),
    }
    asyncio.run(app(scope, receive, send))
    assert captured["status"] == 200
    assert b"".join(bodies) == b"part-one-part-two"


def test_receive_passes_disconnect_through_uncached():
    from guard.asgi import _BodyCachingReceive

    disconnect = {"type": "http.disconnect"}

    async def inner():
        return disconnect

    receive = _BodyCachingReceive(inner)
    message = asyncio.run(receive())
    assert message is disconnect


def test_non_http_scopes_pass_through():
    calls: list[str] = []

    class ProbeApp:
        async def __call__(self, scope, receive, send):
            calls.append(scope["type"])

    middleware = PureASGISecurityMiddleware(ProbeApp(), config=_base_config())
    asyncio.run(middleware.__call__({"type": "lifespan"}, lambda: None, lambda _: None))
    assert calls == ["lifespan"]


class _FakeAgent:
    def __init__(self) -> None:
        self.metrics: list[Any] = []

    async def send_metric(self, metric: Any) -> None:
        self.metrics.append(metric)


def _metrics_app(config: SecurityConfig, agent: _FakeAgent) -> FastAPI:
    from starlette.responses import StreamingResponse

    app = FastAPI()
    mw_holder: dict[str, Any] = {}

    class Spy(PureASGISecurityMiddleware):
        def __init__(self, app_, *, config):
            super().__init__(app_, config=config)
            self._engine.metrics_collector.agent_handler = agent
            mw_holder["mw"] = self

    app.add_middleware(Spy, config=config)

    @app.get("/ok")
    async def ok():
        return {"ok": True}

    @app.get("/boom")
    async def boom():
        return JSONResponse({"e": 1}, status_code=503)

    @app.get("/stream")
    async def stream():
        async def gen():
            for i in range(3):
                yield f"chunk{i}".encode()

        return StreamingResponse(gen())

    return app


def _metric_summary(agent: _FakeAgent) -> list[tuple[str, str | None]]:
    return [(m.metric_type, m.tags.get("status")) for m in agent.metrics]


def test_pure_asgi_emits_request_metrics_once():
    agent = _FakeAgent()
    config = _base_config(agent_enable_metrics=True)

    async def runner():
        transport = ASGITransport(
            app=_metrics_app(config, agent), client=(_unique_ip(), 50000)
        )
        async with AsyncClient(transport=transport, base_url="http://t") as client:
            assert (await client.get("/ok")).status_code == 200

    asyncio.run(runner())
    assert sorted(_metric_summary(agent)) == [
        ("request_count", None),
        ("response_time", "200"),
    ]
    rt = next(m for m in agent.metrics if m.metric_type == "response_time")
    assert rt.value >= 0


def test_pure_asgi_emits_error_rate_for_5xx():
    agent = _FakeAgent()
    config = _base_config(agent_enable_metrics=True)

    async def runner():
        transport = ASGITransport(
            app=_metrics_app(config, agent), client=(_unique_ip(), 50000)
        )
        async with AsyncClient(transport=transport, base_url="http://t") as client:
            assert (await client.get("/boom")).status_code == 503

    asyncio.run(runner())
    assert sorted(_metric_summary(agent)) == [
        ("error_rate", "503"),
        ("request_count", None),
        ("response_time", "503"),
    ]


def test_pure_asgi_streaming_unbuffered_and_counted_once():
    agent = _FakeAgent()
    config = _base_config(agent_enable_metrics=True)
    bodies: list[bytes] = []

    async def runner():
        mw = _metrics_app(config, agent)
        sent: list[dict[str, Any]] = []

        delivered = False

        async def receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await asyncio.Event().wait()  # client stays connected

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "path": "/stream",
            "raw_path": b"/stream",
            "query_string": b"",
            "headers": [],
            "client": (_unique_ip(), 50000),
            "server": ("t", 80),
            "scheme": "http",
            "root_path": "",
        }
        await mw(scope, receive, send)
        bodies.extend(
            m["body"] for m in sent if m["type"] == "http.response.body" and m["body"]
        )

    asyncio.run(runner())
    assert bodies == [b"chunk0", b"chunk1", b"chunk2"]
    assert _metric_summary(agent).count(("request_count", None)) == 1


def test_pure_asgi_no_metrics_when_downstream_sends_no_response():
    agent = _FakeAgent()
    config = _base_config(agent_enable_metrics=True)

    async def silent_app(scope, receive, send):
        return None

    async def runner():
        mw = PureASGISecurityMiddleware(silent_app, config=config)
        mw._engine.metrics_collector.agent_handler = agent

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            pass

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/x",
            "raw_path": b"/x",
            "query_string": b"",
            "headers": [],
            "client": (_unique_ip(), 50000),
            "server": ("t", 80),
            "scheme": "http",
            "root_path": "",
        }
        await mw(scope, receive, send)

    asyncio.run(runner())
    assert agent.metrics == []


def test_pure_asgi_response_time_stops_at_response_start(monkeypatch):
    import guard.asgi as asgi_mod

    agent = _FakeAgent()
    config = _base_config(agent_enable_metrics=True)
    clock = {"now": 100.0}
    monkeypatch.setattr(asgi_mod.time, "time", lambda: clock["now"])

    async def slow_body_app(scope, receive, send):
        clock["now"] += 2.0
        await send({"type": "http.response.start", "status": 200, "headers": []})
        clock["now"] += 50.0
        await send({"type": "http.response.body", "body": b"x"})

    async def runner():
        mw = PureASGISecurityMiddleware(slow_body_app, config=config)
        mw._engine.metrics_collector.agent_handler = agent

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            pass

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/x",
            "raw_path": b"/x",
            "query_string": b"",
            "headers": [],
            "client": (_unique_ip(), 50000),
            "server": ("t", 80),
            "scheme": "http",
            "root_path": "",
        }
        await mw(scope, receive, send)

    asyncio.run(runner())
    rt = next(m for m in agent.metrics if m.metric_type == "response_time")
    assert rt.value == 2.0
