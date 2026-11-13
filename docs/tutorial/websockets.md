---

title: WebSockets - FastAPI Guard
description: Securing WebSocket routes with the guard_websocket dependency
keywords: websocket, guard_websocket, dependency injection
---

WebSockets
==========

`SecurityMiddleware` protects HTTP requests only. It is built on Starlette's `BaseHTTPMiddleware`, which never runs its `dispatch` method for a `"websocket"` ASGI scope; a `@app.websocket` route registered on the same app receives zero protection from the middleware, regardless of configuration.

___

The guard_websocket Dependency
-------------------------------

Secure a WebSocket route explicitly with `Depends(guard_websocket)`:

```python
from fastapi import Depends, FastAPI, WebSocket

from guard import SecurityConfig, SecurityMiddleware, guard_websocket

app = FastAPI()
app.add_middleware(
    SecurityMiddleware,
    config=SecurityConfig(
        trusted_proxies=["10.0.0.1"],
        blacklist=("203.0.113.9",),
    ),
)


@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket, _: None = Depends(guard_websocket)
) -> None:
    await websocket.accept()
    await websocket.send_text("connected")
```

`guard_websocket` runs before the route function, using the same `SecurityConfig` passed to `app.add_middleware(SecurityMiddleware, config=...)`. The route's own rules come from the endpoint function: decorate it with the app's `SecurityDecorator` (the one registered as `app.state.guard_decorator`) and the handshake enforces them. In order, it checks:

1. Emergency mode -- guard-core's `EmergencyModeCheck`, the same check the HTTP pipeline runs: while `emergency_mode` is on, a client outside the emergency whitelist is refused on every path, `exclude_paths` entries included, except the paths in `emergency_exempt_paths`.
2. HTTPS enforcement -- guard-core's `HttpsEnforcementCheck` when `enforce_https` is on or the endpoint is decorated with `require_https`. `wss` counts as HTTPS, as does `X-Forwarded-Proto: https` from a trusted proxy. A handshake cannot be redirected, so the refusal closes the socket.
3. Request logging -- guard-core's `RequestLoggingCheck` when `log_request_level` is set.
4. `ip_ban_manager.is_ip_banned` -- is the resolved client IP currently banned.
5. `is_ip_allowed` -- whitelist/blacklist, blocked countries, blocked cloud providers.
6. Cloud providers -- `CloudIpRefreshCheck` and `CloudProviderCheck` when `block_cloud_providers` is set (or the endpoint is decorated with `block_clouds`), skipped for a whitelisted client.
7. User agent -- guard-core's `UserAgentCheck`, the same check the HTTP pipeline runs: `blocked_user_agents` and `block_empty_user_agent`, and the endpoint's own `blocked_user_agents`, skipped for a whitelisted client and for an `exclude_paths` entry.
8. `check_rate_limit_by_ip` -- a rate-limit bucket isolated from the HTTP pipeline's own bucket for the same IP (keyed by `endpoint_path="ws"`), Redis-backed when `enable_redis=True`, in-memory otherwise.
9. The endpoint's route rules -- `RequiredHeadersCheck`, `AuthenticationCheck`, `ReferrerCheck`, `CustomValidatorsCheck` and `TimeWindowCheck`, each only when the endpoint's decorator asks for it.
10. Penetration detection -- the handshake's headers, cookies, query string and path are scanned by guard-core's `SuspiciousActivityCheck`, the same detection guard-core's HTTP pipeline runs on a request, honouring `enable_penetration_detection`, `passive_mode`, `exclude_paths` and the whitelist and auto-ban rules above; there is no body to scan on a handshake.
11. The custom request check -- guard-core's `CustomRequestCheck` when `custom_request_check` is set.

Three engine checks do not run on a handshake, each for a reason that comes from the protocol: the route-resolution check (`RouteConfigCheck`) answers an unresolved route with an HTTP status and the socket is already routed when the dependency runs, `CorsPreflightCheck` only answers an `OPTIONS` preflight and a handshake is a `GET`, `RequestSizeContentCheck` limits a request body and a handshake has none. The route-level overrides of the ban, IP-list and rate-limit checks (a decorator's `require_ip` or `rate_limit` on the endpoint) are not applied to a handshake yet.

On the first failing check, the connection is closed with WebSocket close code `1008` (Policy Violation), or `1013` (Try Again Later) for emergency mode and for a failed check, before `accept()` is ever called; the client sees the handshake rejected, not an accepted-then-closed connection.

With `passive_mode=True` no check refuses a handshake, exactly as no check refuses an HTTP request: each one that would have refused logs the same `[PASSIVE MODE]` line the HTTP pipeline logs, runs the `on_block` hook, and the handshake is accepted.

If Redis is unreachable while `ip_ban_manager.is_ip_banned` or `check_rate_limit_by_ip` runs, `guard_websocket` follows the same `redis_fail_open` and `fail_secure` rules as the HTTP pipeline: `redis_fail_open=True` skips the failing check and treats it as passed; otherwise `fail_secure=True` (the default) refuses the handshake with close code `1013` (Try Again Later); otherwise the check is skipped and the error is logged.

When `enable_redis=True` and the app's Redis handler is not connected yet, `guard_websocket` runs the same lazy initialization the HTTP `SecurityMiddleware` runs on its first request, so a WebSocket-first worker uses Redis for its rate limit like HTTP does. If Redis is unreachable at that moment, the handshake is refused with close code `1013` (Try Again Later) where HTTP answers `503` with `Retry-After`; `redis_fail_open=True` admits it with the in-memory store, and `passive_mode=True` logs the refusal and admits it. The next handshake retries, so no restart is needed once Redis is back. A WebSocket-only app (no HTTP route ever warms the middleware) should wire `make_lifespan()` into `FastAPI(lifespan=...)` so initialization happens at startup instead of on the first handshake.

`websocket.state.is_whitelisted` is `True` only for a client that is on the global `SecurityConfig.whitelist` (and `whitelist_access_only=False`): membership decides it, as in the HTTP pipeline. For that client the rate-limit check is skipped, mirroring the HTTP rule that a whitelisted request never reaches `RateLimitCheck`. A client off the list is rejected by the allow-list check, and under `passive_mode` (which logs that refusal and admits the handshake) it is rate limited and scanned like any other client.

___

The make_guard_websocket Factory
---------------------------------

`make_guard_websocket(config: SecurityConfig)` returns a dependency bound to that exact `SecurityConfig`, independent of `SecurityMiddleware` registration. It runs the identical checks as `guard_websocket`, in the same order, sharing one private implementation, so it is not a reduced or divergent code path -- it is the same guard, given its config directly instead of resolving it from the middleware.

This is useful for a WebSocket route on an app that has no `SecurityMiddleware` at all (an app that guards WebSocket traffic only), or in tests that want to exercise the guard without standing up the full HTTP middleware:

```python
from fastapi import Depends, FastAPI, WebSocket

from guard import SecurityConfig, make_guard_websocket

app = FastAPI()

config = SecurityConfig(blacklist=("203.0.113.9",))


@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket, _: None = Depends(make_guard_websocket(config))
) -> None:
    await websocket.accept()
    await websocket.send_text("connected")
```

`guard_websocket` keeps its existing contract: it still raises `RuntimeError` at connection time on an app without a registered `SecurityMiddleware`, even if `make_guard_websocket` is used elsewhere on that same app.

___

Redis-Backed Rate Limiting
----------------------------

`RedisManager` is a process-wide singleton; constructing one with a different `SecurityConfig` rebinds the connection for every other caller in the process, including the HTTP pipeline. Neither `guard_websocket` nor `make_guard_websocket` ever constructs a `RedisManager` themselves.

`guard_websocket` resolves the already-initialized manager that `SecurityMiddleware` created for the same `SecurityConfig`; if `enable_redis=True` but that manager has not connected yet, the rate-limit check falls back to the in-memory store for that connection rather than forcing a connection or touching the singleton.

`make_guard_websocket(config, redis_handler=None)` takes the manager explicitly instead: pass an already-initialized `RedisManager` to back the websocket rate limit with Redis, or leave it `None` to use the in-memory store. Passing `enable_redis=True` with no `redis_handler` logs one warning when the dependency is created (not on every connection) and then rate-limits in memory for the lifetime of that dependency:

```python
from guard import SecurityConfig, make_guard_websocket
from guard_core.handlers.redis_handler import RedisManager

config = SecurityConfig(redis_url="redis://localhost:6379", enable_redis=True)
redis_handler = RedisManager(config)
await redis_handler.initialize()

dependency = make_guard_websocket(config, redis_handler=redis_handler)
```

___

Client Resolution
------------------

The client IP is resolved the same way as the HTTP pipeline: `websocket.client.host` if the connection has a peer, or `X-Forwarded-For` when the connecting peer is a trusted proxy (`trusted_proxies`, `trusted_proxy_depth`). A connection with no peer at all (a Unix domain socket, some serverless adapters) needs `"unix"` in `trusted_proxies` to resolve from `X-Forwarded-For`, exactly as for HTTP; see [Proxy Security](security/proxy-security.md#unix-sockets-and-serverless-adapters).

When the client address still cannot be resolved, `guard_websocket` follows the same `fail_secure` setting as the HTTP pipeline: `fail_secure=True` (the default) closes the connection with code `1008` before running any further check, except under `passive_mode`, where the refusal is only logged (and `on_block` is called) and the handshake goes on; `fail_secure=False` runs the ban, allow-list, and blocked-country checks against identity `"unknown"` (allowed unless a whitelist or a country allow-list is configured) and skips the rate-limit check, since there is no real IP to key a rate-limit bucket on.

___

Close Code Contract
--------------------

`guard` exports module-level `(code, reason)` constants for every close outcome `guard_websocket`/`make_guard_websocket` can emit, and neither ever raises any pair outside this set. Log processing can key on the `reason` string directly, or import the constants:

```python
from guard import (
    WS_CLOSE_CLIENT_ADDRESS_UNKNOWN,
    WS_CLOSE_EMERGENCY_MODE,
    WS_CLOSE_IP_BANNED,
    WS_CLOSE_IP_NOT_ALLOWED,
    WS_CLOSE_RATE_LIMIT_EXCEEDED,
    WS_CLOSE_REASONS,
    WS_CLOSE_SECURITY_CHECK_FAILED,
    WS_CLOSE_SUSPICIOUS_ACTIVITY,
    WS_CLOSE_USER_AGENT_NOT_ALLOWED,
    WS_CLOSE_AUTHENTICATION_REQUIRED,
    WS_CLOSE_CLOUD_PROVIDER_BLOCKED,
    WS_CLOSE_CUSTOM_REQUEST_REFUSED,
    WS_CLOSE_HTTPS_REQUIRED,
    WS_CLOSE_OUTSIDE_TIME_WINDOW,
    WS_CLOSE_REFERRER_REQUIRED,
    WS_CLOSE_REQUIRED_HEADER_MISSING,
    WS_CLOSE_VALIDATION_FAILED,
    WebSocketCloseReason,
)
```

Each constant is a `WebSocketCloseReason(code, reason)` named tuple; `WS_CLOSE_REASONS` collects all sixteen.

| Code | Reason                                    | Cause                                                     |
| ---- | ------------------------------------------ | ---------------------------------------------------------- |
| 1008 | `IP banned`                                | `ip_ban_manager.is_ip_banned` returned `True`.              |
| 1008 | `IP not allowed`                           | `is_ip_allowed` returned `False` (whitelist/blacklist, blocked country, blocked cloud provider). |
| 1008 | `Rate limit exceeded`                      | `check_rate_limit_by_ip` returned `False`.                  |
| 1008 | `Client address could not be determined`   | No resolvable client identity, `fail_secure=True` and not `passive_mode` (passive mode logs it and admits the handshake). |
| 1013 | `Security check failed`                    | A Redis error during the ban or rate-limit check, or during detection, with `redis_fail_open=False` and `fail_secure=True`; also an exception inside the emergency-mode or user-agent check under `fail_secure=True`. |
| 1008 | `Suspicious activity detected`             | guard-core's `SuspiciousActivityCheck` flagged the handshake in active mode (`passive_mode=False`). |
| 1013 | `Service temporarily unavailable`          | `emergency_mode` is on and the client is outside the emergency whitelist, on a path not in `emergency_exempt_paths`. |
| 1008 | `User agent not allowed`                   | The `User-Agent` matched `blocked_user_agents`, or was empty with `block_empty_user_agent=True`. |
| 1008 | `HTTPS required`                           | `enforce_https` (or the endpoint's `require_https`) and the handshake is not `wss`. |
| 1008 | `Cloud provider IP not allowed`            | `CloudProviderCheck` matched the client to a blocked cloud provider. |
| 1008 | `Required header missing`                  | The endpoint's `require_headers` is not met. |
| 1008 | `Authentication required`                  | The endpoint's authentication or authorization-header rule is not met. |
| 1008 | `Referrer not allowed`                     | The endpoint's `require_referrer` is not met. |
| 1008 | `Request validation failed`                | A `custom_validation` of the endpoint refused the handshake. |
| 1008 | `Access outside the allowed time window`   | The endpoint's `time_window` does not include now. |
| 1008 | `Request refused`                          | `custom_request_check` returned a response. |

Every close in this table happens before `accept()`, so the `reason` string reaches the server's own logs only, not the browser: uvicorn answers a pre-accept close with plain HTTP `403` and discards the WebSocket close code and reason entirely (uvicorn's `websockets_impl.py:296-303`), so the client sees a failed upgrade with status `403`, never the `(code, reason)` pair. Read the pair in the application's own logging, for example a handler around `WebSocketException`, not on the client.

A Redis failure during `ip_ban_manager.is_ip_banned` follows `redis_fail_open` and `fail_secure` exactly as described above: with `redis_fail_open=False` and `fail_secure=False`, the failure is treated as "not banned", the same fail-open default the HTTP pipeline uses for this case; only `fail_secure=True` produces the `1013` close.

What `check_rate_limit_by_ip` does with a Redis failure depends on the guard-core version. With guard-core older than 3.15.0 it catches the error internally, logs it on every request, and falls back to the same per-process in-memory window used when `enable_redis=False`, on both the HTTP pipeline and here; it never raises, so the `1013` close is reachable only through the ban check. From guard-core 3.15.0 it follows `redis_fail_open`: with `redis_fail_open=False` (the default) a Redis failure raises `GuardRedisError`, which under `fail_secure=True` becomes a 500 on the HTTP pipeline and the `1013` close here, and is passed through otherwise; with `redis_fail_open=True` the in-memory fallback is kept and the failure is logged once per process instead of on every request. In either case, while the fallback is active with more than one worker process, the effective limit is `rate_limit` multiplied by the worker count, since each process counts independently.

___

Client IP on websocket.state
------------------------------

Immediately after the client identity is resolved, and before any check runs, `guard_websocket` and `make_guard_websocket` set `websocket.state.client_ip` to that resolved value -- including the literal string `"unknown"` when no client address could be determined and `fail_secure=False` let the connection proceed. A route handler can read `websocket.state.client_ip` after `accept()` to log or reuse the identity the guard already resolved, without re-deriving it from headers.

___

Scope
-----

`guard_websocket` scans the handshake for penetration attempts the same way the HTTP pipeline scans a request, but it does not run security headers, HTTPS enforcement, or any per-route decorator; those are HTTP-pipeline concepts with no WebSocket equivalent. It requires `SecurityMiddleware` to already be registered on the app (`app.add_middleware(SecurityMiddleware, config=...)`); calling it without that raises `RuntimeError` at connection time.
