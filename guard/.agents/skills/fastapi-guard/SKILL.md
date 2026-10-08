---
name: fastapi-guard
description: Production-ready security middleware for FastAPI. Use when adding IP filtering, rate limiting, per-route security decorators, route-resolution strict mode, global behavior rules, passive/log-only mode, or Guard Agent SaaS telemetry to a FastAPI app. Covers SecurityMiddleware setup, SecurityConfig tuning, and the guard-agent buffer/flush footgun.

---

# FastAPI Guard

Security middleware for FastAPI: IP filtering, rate limiting, signature-based attack-pattern detection, and 20+ per-route security decorators. Import package is `guard` (distribution name `fastapi-guard`).

## Quick Reference

* Install: `uv add fastapi-guard` (or `pip install fastapi-guard`). Optional SaaS telemetry: `pip install fastapi-guard[agent]`.
* Add the middleware on `FastAPI` with `SecurityMiddleware(app, config=SecurityConfig(...))`; see [Setup](#setup).
* IP filtering: `whitelist` (restrictive) and `blacklist` (CIDR/IP); see [the IP filtering reference](references/ip-filtering.md).
* Rate limiting: `enable_rate_limiting`, `rate_limit`, `rate_limit_window`, `endpoint_rate_limits`; see [the rate limiting reference](references/rate-limiting.md).
* Per-route rules: compose `SecurityDecorator` decorators (`@guard.rate_limit(...)`, `@guard.ip_filter(...)`, etc.).
* Decorator visibility shrinks the pipeline: checks that only decorators can trigger (auth, referrer, required headers, custom validators, time window, request size/content type) run only when the middleware can see the registered route config, via `set_decorator_handler` or `app.state.guard_decorator`; see [the route resolution reference](references/route-resolution.md).
* Strict routing: `route_resolution_strict=True` blocks unresolved routes instead of passing them through; see [the route resolution reference](references/route-resolution.md).
* Global behavior rules: `global_behavior_rules` apply to every route (e.g. 404 watchers); see [the route resolution reference](references/route-resolution.md).
* Passive mode: `passive_mode=True` logs but never blocks; see [Passive Mode](#passive-mode).
* Guard Agent telemetry: `enable_agent=True` plus the `agent_*` fields; see [the agent integration reference](references/agent-integration.md).

## Installation

```bash
uv add fastapi-guard                # or: pip install fastapi-guard
pip install "fastapi-guard[agent]"  # optional: guard-agent SaaS telemetry
```

The import package is `guard` (distribution name `fastapi-guard`). Supports Python 3.10-3.14.

## Setup

```python
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware

app = FastAPI()

config = SecurityConfig(
    enable_rate_limiting=True,
    rate_limit=30,
    rate_limit_window=60,
    enable_ip_banning=True,
    auto_ban_threshold=5,
    auto_ban_duration=86400,
    block_cloud_providers={"AWS", "GCP", "Azure"},
)

app.add_middleware(SecurityMiddleware, config=config)
```

For production, wire `guard.lifespan.guard_lifespan` into `FastAPI(lifespan=...)` so initialization runs at app startup instead of on the first request:

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware
from guard.lifespan import guard_lifespan

config = SecurityConfig(enable_rate_limiting=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with guard_lifespan(app):
        yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(SecurityMiddleware, config=config)
```

`SecurityMiddleware` is a Starlette `BaseHTTPMiddleware`. Construct one `SecurityConfig` and pass the same instance to both the middleware and the lifespan. `guard_lifespan`, `make_lifespan`, and `guard_startup` all warm the same shared-state registry, keyed on both the `SecurityConfig` instance and the resolved decorator handler: a second `SecurityMiddleware` built from the same `config` only adopts the first instance's pipeline and handlers when it also resolves to the same decorator handler, and builds its own otherwise. This matters once the pipeline is derived from route config (see [the route resolution reference](references/route-resolution.md)): two instances sharing one `SecurityConfig` but decorating different routes must not share a pipeline, or the second app would silently inherit checks the first app's routes eliminated.

## Per-Route Security Decorators

Compose rules at the endpoint level with `SecurityDecorator`:

```python
from fastapi import FastAPI
from guard import SecurityConfig, SecurityDecorator

config = SecurityConfig(
    auth_verifier=lambda request, credential: {"user": "demo"} if credential else None,
)
guard = SecurityDecorator(config)

app = FastAPI()
app.add_middleware(SecurityMiddleware, config=config)


@app.get("/api/payments")
@guard.rate_limit(max_requests=10, window_seconds=60)
@guard.require_auth(type="bearer")
async def list_payments():
    return []
```

`require_auth` and `api_key_auth` require a verifier: a callable `verifier(request, credential) -> Principal | None` supplied per route via `verifier=` or globally via `SecurityConfig.auth_verifier`. Without one the request is rejected with 401 fail-closed. The principal lands on `request.state.auth_principal`. For a presence-only `Authorization` header gate that is NOT authentication, use `@guard.require_authorization_header(scheme="bearer")`; it is mutually exclusive with `require_auth` and `api_key_auth`.

Decorators are composable and stack top-down. Each one writes a per-route `RouteConfig` that the middleware resolves at request time.

## IP Filtering

`whitelist` is restrictive: when non-empty, only listed IPs/CIDRs pass the global IP check. `blacklist` is enforced ahead of country and cloud-provider checks. An explicit whitelist match overrides the blacklist; dynamic IP bans still apply to both.

```python
config = SecurityConfig(
    whitelist=["10.0.0.0/8", "192.168.1.1"],
    blacklist=["203.0.113.0/24"],
    enable_ip_banning=True,
    auto_ban_threshold=5,
    auto_ban_duration=86400,
)
```

See [the IP filtering reference](references/ip-filtering.md) for country rules, cloud-provider blocking, and the geo IP handler.

## Rate Limiting

Global limit plus optional per-endpoint overrides. Redis is used for distributed state when `enable_redis=True` (default); without Redis, limits are per-process.

```python
config = SecurityConfig(
    enable_rate_limiting=True,
    rate_limit=100,
    rate_limit_window=60,
    endpoint_rate_limits={"/api/login": (5, 60)},
)
```

See [the rate limiting reference](references/rate-limiting.md) for the decorator form and Redis notes.

## Route Resolution Strict Mode

By default (`route_resolution_strict=False`), a request whose route cannot be resolved runs the pipeline with no per-route config, so undecorated routes and unrouted paths pass through. Set `True` when every request must be attributable to a known route:

```python
config = SecurityConfig(route_resolution_strict=True)
```

Note: this also turns requests to paths the app does not serve into 500s instead of 404s. See [the route resolution reference](references/route-resolution.md).

## Global Behavior Rules

`global_behavior_rules` apply to every route in addition to any decorator-specified rules. Useful for global 404 watchers or request-volume thresholds:

```python
from guard import BehaviorRule, SecurityConfig

config = SecurityConfig(
    global_behavior_rules=[
        BehaviorRule(action="log", reason="global_404_watch"),
    ],
)
```

See [the route resolution reference](references/route-resolution.md) for rule shape and ordering.

## Passive Mode

`passive_mode=True` runs every check in log-only mode: suspicious requests are logged but never blocked. Use it to trial rules against production traffic before enforcing them.

```python
config = SecurityConfig(
    passive_mode=True,
    global_behavior_rules=[BehaviorRule(action="log", reason="shadow")],
)
```

Switch to `passive_mode=False` once the log output shows the rules firing on the traffic you expect.

## Guard Agent Telemetry

`enable_agent=True` ships security events and metrics to the Guard SaaS. Requires the `guard-agent` package (`pip install fastapi-guard[agent]`). Without it installed, the middleware degrades to agent-off unless `agent_strict=True` raises at init.

```python
config = SecurityConfig(
    enable_agent=True,
    agent_api_key="...",
    agent_project_id="...",
    agent_buffer_size=100,
    agent_flush_interval=30,
)
```

The buffer/flush defaults (100 events, 30s) are safe. Do not raise `agent_buffer_size` toward thousands while shortening `agent_flush_interval`; see [the agent integration reference](references/agent-integration.md) for the 256 KiB ingestion cap and 413 split-or-drop behavior.

## Footguns

* **Keep `agent_buffer_size` small.** The SaaS ingestion endpoint caps request bodies at 256 KiB. A large buffer that flushes a giant batch triggers a 413 and forces a split-or-drop cascade; do not raise `agent_buffer_size` toward thousands while shortening `agent_flush_interval`. The defaults (100 events, 30s) are safe.
* **Two middleware instances sharing one `SecurityConfig` do not necessarily share a pipeline.** Shared state is keyed on both the config instance and the resolved decorator handler; two apps decorating different routes must not share a pipeline, or the second would silently inherit checks the first app's routes eliminated. See [Setup](#setup).
* **`route_resolution_strict=True` turns unknown paths into 500s, not 404s.** Requests to paths the app does not serve cannot resolve a route, so strict mode rejects them; enable it only when every request must be attributable to a known route.
* **`require_auth`/`api_key_auth` without a verifier 401s fail-closed.** Supply `verifier=` per route or `SecurityConfig.auth_verifier` globally. `require_authorization_header(scheme=...)` is presence-only, is NOT authentication, and cannot be combined with either.
* **`passive_mode=True` never blocks.** Every check logs and emits events but lets the request pass; do not assume protection while trialing rules in passive mode.

## Exports

`guard` re-exports the public surface from `guard_core`: `SecurityMiddleware`, `SecurityConfig`, `SecurityDecorator`, `RouteConfig`, `BehaviorRule`, `BehaviorTracker`, `IPBanManager`, `IPInfoManager`, `RateLimitManager`, `RedisManager`, `RedisHandlerProtocol`, `GeoIPHandler`, `GuardRequest`, `GuardResponse`, `GuardResponseFactory`, `SecurityHeadersManager`, `CloudManager`, and the singletons `cloud_handler`, `ip_ban_manager`, `rate_limit_handler`, `redis_handler`, `security_headers_manager`, `sus_patterns_handler`.

## Tooling

* Docs: <https://guard-core.github.io/fastapi-guard/latest/>
* Playground: <https://playground.guard-core.com>
* Dashboard: <https://app.guard-core.com>
* Use `uv` for package management and Ruff for linting when applicable.

## Related Projects

* [guard-core](https://github.com/Guard-Core/guard-core): framework-agnostic security engine this adapter wraps.
* [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard): Flask extension adapter (sync mirror).
* [djapi-guard](https://github.com/Guard-Core/djapi-guard): Django middleware adapter (sync mirror).
* [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard): Tornado handler/middleware adapter.
* [guard-agent](https://github.com/Guard-Core/guard-agent): telemetry client used by `enable_agent=True`.
* [guard-core-mcp](https://github.com/Guard-Core/guard-core-mcp): MCP server for config validation and docs search.
* [guard-core-app](https://github.com/Guard-Core/guard-core-app): SaaS platform the agent reports to.
