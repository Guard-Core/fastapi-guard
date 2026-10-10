Release Notes
=============

___

v8.1.0 (2026-10-10)
-------------------

The pure-ASGI release: the full screening pipeline without BaseHTTPMiddleware (v8.1.0)
----------------------------------------------------------------------------------------------------------------

Added
-----

- **`PureASGISecurityMiddleware`: the full screening pipeline on raw ASGI** (fastapi-guard #156). Runs initialization, CORS preflight, path exclusions, IP extraction, ban lists, rate limiting, user-agent blocking, penetration detection and behavioral usage rules without `BaseHTTPMiddleware` - no anyio task group wraps the downstream app, so client disconnects can never cancel in-flight database calls, and responses stream through unbuffered. Body reads go through a caching receive that replays to the application; security and CORS headers are injected directly on `http.response.start`; WebSocket and lifespan scopes pass through untouched. Built for frameworks that ban `BaseHTTPMiddleware` by policy (open-webui carries a written rationale in main.py) and for the RFC thread asking for exactly this shape.
- Scope note: decorator-driven response rules (return patterns) and `custom_response_modifier` need a materialized `Response` object and stay on the classic middleware; both classes ship side by side and the classic one is unchanged.

___

v8.0.3 (2026-10-08)
-------------------

Guard-Core org migration
------------------------

Metadata release: PyPI project URLs, the docs canonical domain, and all repository links moved to the Guard-Core org. No code changes.

___

v8.0.2 (2026-09-26)
-------------------

Community fixes and exempt_ips lockstep: trailing-slash route config, block response Content-Type, live-smoke exempt_ips scenario; guard-core 4.1.0 tracking (v8.0.2)
---------------------------------------------------------------------------------------------------------------------------------------------------------------------

- **Fixed** - Route decorator config now resolves through Starlette's trailing-slash redirect (#142): when the request path matches no route but toggling the trailing slash does, the middleware reads the config of the route Starlette would 307-redirect to, so a route override registered on `/path` now governs a request to `/path/` (and vice versa) instead of silently falling through to the global defaults. Each router decides with its own `redirect_slashes` (mounted apps for their paths, the including app for an included router's routes), the root path and directly matched requests are untouched.
- **Fixed** - Block responses now declare `Content-Type: text/plain` (#144): the Starlette response factory left Starlette's media type unset, so middleware-generated 403/429/400 pages went out without a content type and clients were left guessing. The factory now passes `media_type="text/plain"`, matching the engine's reference response factory.
- **Tests** - New live-smoke scenario `tests/live_smoke/scenarios/exempt_ips.py` (#145) covering the guard-core `exempt_ips` skip-list end to end through the live stack: an exempt IP exceeding `rate_limit` keeps getting 200 across the crossing while no rate-limit bucket is written for it at all (`smoke:rate_limit:rate:<ip>` stays absent in Redis, pinning that the exempt skip sits ahead of the limiter), a penetration-detection payload from the exempt IP still gets 400 (exemption is not immunity), the identical sequence without `exempt_ips` throttles at the crossing with 429 and leaves exactly the bucket the exempt run never wrote, and an IP that is both exempt and blacklisted gets 403 (blacklist beats exemption). The scenario merged red against PyPI guard-core (< 4.1.0) by design, the documented lockstep hold; with this release it runs green against the published 4.1.0 engine in CI.
- **Compatibility** - The `guard-core` floor rises from `>=4.0.0` to `>=4.1.0` and this release tracks the guard-core 4.1.0 engine (the exempt_ips skip-list, the recon leading-separator gate, the raw-view recon scan, the cross-engine interop harness). Both fixed behaviors are adapter-side; no guard-core API fastapi-guard uses changed shape.

v8.0.1 (2026-09-23)
-------------------

CI hardening, live smoke suite, agent docs; guard-core 4.0.4 tracking (v8.0.1)
------------------------------------------------------------------------------

- **CI** - Added a DockSec container scan with SARIF upload to the pipeline (#138) and removed the Slack notification steps from all workflows.
- **CI** - New live smoke suite (`tests/live_smoke/`): a Docker Compose stack (nginx, gunicorn, Redis) running the full example app is exercised against PRs, and a nightly upstream drift gate builds the suite against guard-core master so engine-side regressions surface before a release instead of after (#134).
- **Fixed (tests)** - `test_cloud_ip_blocking_with_logging` (`tests/test_middleware/test_security_middleware.py`) now awaits the scheduled background cloud-IP refresh before asserting instead of relying on a stale Redis handler left behind by another test to suspend the dispatch (#136).
- **Documentation** - Added `AGENTS.md`/`CLAUDE.md` agent guidance and extended the fastapi-guard package skill.
- **Compatibility** - No production code changed: the delta since 8.0.0 is CI, tests and docs only, hence the patch bump. The `guard-core>=4.0.0` floor is unchanged and this release tracks the guard-core 4.0.4 engine.

___

v8.0.0 (2026-09-04)
-------------------

Lockstep with guard-core 4.0.0: log_activity assertions, timestamp serialisation, unban wiring, throttle docs, hsts None guard (v8.0.0)
---------------------------------------------------------------------------------------------------------------------------------------

- **Compatibility (dependency floor, breaking for anyone pinned below 4.0.0)** - `guard-core` floor moves from `>=3.14.0` to `>=4.0.0` in `pyproject.toml`, no upper bound. guard-core 4.0.0 carries breaking changes of its own (grammar-based secret redaction, `require_headers()` now enforces an exact value match for any configured value other than `"required"`, `excluded_detection_headers` no longer fully silences a header) which do not require any change in this release's own code or tests, since fastapi-guard's `require_headers()` usage in its examples and tests only ever exercises the presence-only `"required"` value or sends a header value matching what is configured, and neither fastapi-guard's code nor its tests set `excluded_detection_headers`. See the guard-core 4.0.0 changelog for the full engine-side list.
- **Requires (lockstep)** - fastapi-guard 8.0.0 tracks guard-core 4.0.0. guard-core 4.0.0 is not yet published to PyPI as of this release commit; CI resolves `guard-core>=4.0.0` fresh from PyPI (`uv.lock` is gitignored) and will fail until it is. This release is held locally, matching the pattern set by earlier lockstep releases, until guard-core 4.0.0 ships.
- **Tests** - `test_cloud_ip_blocking_with_logging` and `test_passive_mode_penetration_detection` (`tests/test_middleware/test_security_middleware.py`) pinned the full `log_activity()` call via `assert_any_call`, which broke against guard-core >=3.16.0's added `on_block`/`sensitive_headers`/`sensitive_params`/`sensitive_body_fields` keyword arguments. Both now check only the kwargs each test cares about as a subset of the actual call (`assert_log_activity_called_with`), tolerating any further keyword arguments guard-core adds.
- **Fixed (examples)** - `http_exception_handler` and `general_exception_handler` (`examples/advanced_app/app/main.py`) dumped `ErrorResponse` with `model_dump()`, leaving `timestamp` as a raw `datetime` that `JSONResponse` cannot encode, turning every error response (for example `/behavior/return-monitor/404`) into an unhandled 500. Both now use `model_dump(mode="json")`.
- **Fixed (examples)** - `/admin/unban-ip` (`examples/advanced_app/app/routes/admin.py`) only logged the unban and never called guard-core's IP ban manager, so a banned IP stayed banned. The route now calls `ip_ban_manager.unban_ip(ip)`.
- **Documentation (examples)** - `action="throttle"` only logs the violation; guard-core never blocks or delays the request for it. Corrected the `/behavior/suspicious-frequency` and `/behavior/behavior-rules` route descriptions and dropped the fabricated `429` response entries that promised otherwise, and corrected the matching lines in `docs/tutorial/decorators/behavioral.md` and `docs/api/behavior-manager.md`.
- **Documentation (examples)** - `/behavior/usage-monitor`'s `responses` entry named a `"block"` action that does not exist in guard-core (the route uses `action="log"` and never returns 429); the entry is removed. `alert` was documented as sending a notification; it is a critical-level log call, same as any other action's telemetry event. Corrected in `examples/advanced_app/app/routes/behavioral.py` and `docs/api/behavior-manager.md`.
- **Fixed** - `SecurityMiddleware._configure_security_headers` (`guard/middleware.py`) called `headers_config.get("hsts", {}).get("max_age")`, which raised `AttributeError` on every request when `security_headers={"hsts": None, ...}` was passed explicitly, since `.get("hsts", {})` returns `None`, not `{}`, for a key present with an explicit `None` value. Now falls back to `{}` the same way guard-core's own `security_headers_handler` treats a missing `hsts` block. guard-core 4.0.0 separately fixes the same class of bug on its own singleton (a stale `hsts`/`csp`/`cors` configuration surviving a reconfigure), so this guard is defense in depth against both the old and the fixed guard-core behavior.
- **Security** - `guard_websocket` and `make_guard_websocket` (`guard/websocket.py`) ran only the IP-ban and rate-limit checks on a WebSocket handshake; an attack riding in the handshake's headers, cookies, query string or path was never detected and never logged. The handshake is now scanned the same way an HTTP request is scanned, through guard-core's own `SuspiciousActivityCheck`, honouring `enable_penetration_detection`, `passive_mode`, `exclude_paths` and the whitelist and auto-ban rules already in place; a detected attack in active mode closes the connection before `accept()` with the new `WS_CLOSE_SUSPICIOUS_ACTIVITY` close reason (code `1008`, collected in `WS_CLOSE_REASONS`), logs and emits the same event and `on_block` payload the HTTP pipeline emits, and redacts sensitive header, query and cookie values exactly as the HTTP pipeline does; passive mode logs and emits without closing the connection.

___

v7.8.2 (2026-08-27)
-------------------

Route-relative path resolution under root_path and mounts, Starlette and FastAPI floors (v7.8.2)
------------------------------------------------------------------------------------------------

- **Fixed** - `StarletteGuardRequest.url_path` and the WebSocket adapter's `_WebSocketGuardRequest.url_path` returned `request.url.path` / `websocket.url.path`, which under an ASGI `root_path` (`uvicorn --root-path`, or a mounted sub-app) includes the mount prefix. guard-core matches that value against `SecurityConfig.exclude_paths` and `endpoint_rate_limits` (an exact dict-key match) and passes it to `custom_request_check` hooks, so a key such as `/api/vault/login` never matched a request actually served at `/mounted/api/vault/login` and every path-keyed control silently stopped applying under a mount. Both adapters now return Starlette's own `get_route_path(scope)`, the same route-relative path Starlette's router already matches routes against.
- **Compatibility** - If `exclude_paths` or `endpoint_rate_limits` keys currently include your `root_path` mount prefix (a workaround for the bug above), remove the prefix after upgrading: those keys now match the route-relative path and a prefixed key silently stops matching. The same applies to `custom_request_check` hooks that branch on `url_path`.
- **Compatibility** - `starlette>=0.35.0` and `fastapi>=0.109.0` are now declared floors (no ceilings). Route-relative path resolution uses `starlette.routing.get_route_path`, which Starlette added in 0.35.0; 0.109.0 is the first FastAPI release that requires that Starlette. Older pairs fail at `import guard` with an `ImportError`.
- **Changed** - Detection input and the reason text of the `Suspicious activity detected` log line now use the route-relative path, while the `GET <url>` part of the same line still shows the full URL including the mount prefix (`url_full` is unchanged), so the two differ under a mount by design.

___

v7.8.1 (2026-08-27)
-------------------

Websocket guard follow-ups: whitelist parity, explicit-config factory, close-code contract, state.client_ip (v7.8.1)
----------------------------------------------------------------------------------------------------------------------

- **Added** - `make_guard_websocket(config: SecurityConfig, redis_handler: RedisManager | None = None)` returns a `Depends`-ready WebSocket dependency bound to an explicit `SecurityConfig`, for a route on an app that never calls `app.add_middleware(SecurityMiddleware, config=...)`; `guard_websocket` is unchanged and still resolves its config from the registered middleware, raising `RuntimeError` without one. Both entry points share one private check coroutine, so every rule applies to both.
- **Added** - `guard` exports module-level `(code, reason)` constants for the five WebSocket close outcomes `guard_websocket`/`make_guard_websocket` can emit (`WS_CLOSE_IP_BANNED`, `WS_CLOSE_IP_NOT_ALLOWED`, `WS_CLOSE_RATE_LIMIT_EXCEEDED`, `WS_CLOSE_CLIENT_ADDRESS_UNKNOWN`, `WS_CLOSE_SECURITY_CHECK_FAILED`, collected in `WS_CLOSE_REASONS`), documented as a stable contract in `docs/tutorial/websockets.md` that a close handler can key logging on.
- **Added** - `websocket.state.client_ip` is now set to the resolved client identity (including `"unknown"`) immediately after resolution, before any check runs, so a route handler can read it after `accept()`.
- **Fixed** - `guard_websocket` and `make_guard_websocket` now skip the rate-limit check for a client that passes a configured global `whitelist`, mirroring guard-core's HTTP rule (`RateLimitCheck.check` returns early once a request is resolved as whitelisted); previously a whitelisted WebSocket client could still be rate-limited.
- **Fixed** - The websocket rate-limit check no longer constructs a `RedisManager` itself. `RedisManager` is a process-wide singleton; constructing one with a different `SecurityConfig` rebinds its connection for every other caller in the process, so `guard_websocket` previously risked overwriting the HTTP pipeline's own Redis manager, and `make_guard_websocket` on an app without `SecurityMiddleware` could construct an uninitialized manager and raise `GuardRedisError` on every connect. `guard_websocket` now resolves the middleware's already-initialized manager instead of constructing one; `make_guard_websocket` takes an optional `redis_handler` parameter and falls back to the in-memory store (logging one warning at dependency creation) when `enable_redis=True` and none is given.

___

v7.8.0 (2026-08-26)
-------------------

Lockstep release tracking guard-core 3.14.0: missing-client rejection, forwarded-header joining, clean Redis-down responses, and WebSocket protection (v7.8.0)
------------------------------------------------------------------------------------------------------------------------------------------------------------

- **Compatibility (dependency floor, breaking for anyone pinned below 3.14.0)** - `guard-core` changes from an unconstrained dependency to `guard-core>=3.14.0` in `pyproject.toml`. `pip install --upgrade fastapi-guard` alone could previously leave an older guard-core in place; against guard-core 3.12.0 that is an `ImportError` at `import guard` time (`check_ip_access`/`check_rate_limit_by_ip`/`is_ip_allowed`, added in 3.13.0). No upper bound; the floor moves with each lockstep release (fg #120).
- **Security (GHSA-8xvm-856x-7hwp)** - `StarletteGuardRequest.headers` now joins repeated field lines (RFC 7230 5.2) before guard-core resolves the client from `X-Forwarded-For`; previously only the first line was visible, letting a client's own forged line hide the real proxy-appended one and rotate past rate limiting.
- **Compatibility (GHSA-634g-4wr8-xwxv)** - A request with no client address is now rejected by default (`fail_secure=True`) instead of skipping the entire security pipeline; this is guard-core 3.14.0's own fix, fastapi-guard's test suite and docs are brought in line with it here. New `"unix"` `trusted_proxies` token for Unix-socket and serverless deployments.
- **Fixed (#76)** - `SecurityMiddleware` no longer crashes with an unhandled 500 (or fails app startup) when Redis is unreachable at initialization. `dispatch` now catches `GuardRedisError` and returns a clean 503 with `Retry-After: 5`, retrying on the next request; the lifespan warmer logs and continues instead of crashing boot.
- **Security (GHSA-63qv-gh36-52qf)** - New `guard_websocket` dependency (`Depends(guard_websocket)`) for `@app.websocket` routes: `SecurityMiddleware` never runs for WebSocket scopes (`BaseHTTPMiddleware` skips non-HTTP), so a banned or blacklisted IP, or one over its rate limit, previously reached `accept()` unchecked. The example app's "WebSocket protection" claim is now true. A Redis failure during the handshake now follows `redis_fail_open` and `fail_secure` the same way the HTTP pipeline does, instead of leaking an unhandled `GuardRedisError`; a fail-secure refusal closes the connection with code 1013.
- **Added (guard-core #81 item 3)** - `add_status_route` now accepts `dependencies=[...]` (FastAPI apps only), so the opt-in `/_guard/status` route can be gated behind an existing auth dependency instead of relying solely on proxy-level restriction.
- **Compatibility (lockstep)** - fastapi-guard 7.8.0 tracks guard-core 3.14.0. guard-core 3.14.0 is not yet published to PyPI as of this release commit; CI resolves `guard-core>=3.14.0` fresh from PyPI (`uv.lock` is gitignored) and will fail until it is. This commit is held locally, matching the pattern set by earlier lockstep releases, until guard-core 3.14.0 ships. See guard-core 3.14.0's release notes for the full engine-side list: bounded in-memory rate-limit and behavior-tracker stores, float anomaly statistics, a per-request scan value cap, the AzureCloud tag fix, GeoIP last-known-good on refresh failure, telemetry secret redaction, ban-address canonicalization, and new SSRF detection forms.

___

v7.7.0 (2026-08-24)
-------------------

Lockstep release tracking guard-core 3.13.0: detection hardening and the breaking auth-verifier requirement (v7.7.0)
--------------------------------------------------------------------------------------------------------------------

- **Security (auth-verifier, breaking)** - `require_auth(type="bearer", verifier=None)` and `api_key_auth(header_name=..., verifier=None)` now require a resolvable verifier, supplied per route via `verifier=` or globally via `SecurityConfig.auth_verifier`; without one the request is rejected with 401 fail-closed. Previously a bare Bearer/Basic prefix or any API-key header value was accepted without validation. The old presence-only behavior is now the separate decorator `require_authorization_header(scheme="bearer")`, documented as NOT authentication and mutually exclusive with the two auth decorators. The verifier contract is `verifier(request, credential) -> Principal | None` (sync or async in ASGI, sync-only in WSGI), and the authenticated principal lands on `request.state.auth_principal`. See GHSA-x96c-fcg2-x2f9, CWE-287.
- **Compatibility (lockstep)** - fastapi-guard 7.7.0 tracks guard-core 3.13.0; guard-core remains an unconstrained dependency in `pyproject.toml` per project policy so fresh installs already resolve 3.13.0; this release is what makes that pairing whole. See guard-core 3.13.0's release notes (its CHANGELOG.md 3.13.0 section / release notes) for the full list, which covers the ReDoS validation backstop, the scan-window mechanism, a new deserialization category (CWE-502), all-category ingestion-bypass closures, and detection widenings.
- **Adapter** - fastapi-guard itself adds no new security logic: it re-exports guard-core's surface unchanged, and the auth methods ride on the already-re-exported `SecurityDecorator`, so there is no adapter-side code change beyond the version and dependency pairing.

___

v7.6.0 (2026-08-14)
-------------------

Bounded body reading: chunked requests are scanned again and response body rules work for the first time (v7.6.0)
-----------------------------------------------------------------------------------------------------------------

- **Added** - **`StarletteGuardRequest` implements guard-core 3.12.0's `BoundedBodyReader` capability.** A request without a usable `Content-Length`, which is every `Transfer-Encoding: chunked` request, previously reached penetration detection as an unreadable body and was waved through unscanned; with guard-core older than 3.12.0 the same request instead triggered the unbounded buffering that GHSA-c2r5-9jw9-m8q5 closed. `read_body_prefix` aggregates at most `max_bytes` (each chunk is sliced before it is collected, locked in by an allocation-tracing regression test); an oversized single ASGI message the server has already delivered is retained once, by reference, for replay, never duplicated. The replaying receive is installed before the first pull, so a timed-out read cannot lose captured data, and the downstream endpoint observes the byte-identical full body provided the middleware is the first reader of the request stream, which it is in every supported configuration (Starlette's request body is single-consumer; an outer ASGI middleware that partially consumes the stream first forfeits that prefix for everyone downstream, adapter or not). Both properties are locked in by end-to-end tests through a real FastAPI app: an attack in a chunked body is blocked with `400 Suspicious activity detected`, and a benign chunked body arrives at the endpoint whole.
- **Fixed** - **Body-based `return_pattern` rules have never worked in any shipped fastapi-guard; they work now, as an opt-in.** Starlette's `BaseHTTPMiddleware.call_next()` always returns a `_StreamingResponse`, whose constructor never sets `.body`; the adapter's `body` property raised `AttributeError`, guard-core's old `hasattr(response, "body")` gate swallowed the exception, and every body rule silently evaluated to no-match while `status:` rules kept working. Anyone who wrote a body rule got silence and a passing config, with no way to discover the rule was dead. `StarletteGuardResponse` now implements `BoundedResponseBodyReader` as a tee: it reads the first streamed chunk (a non-streaming response is scanned whole) up to `behavior_max_response_body_inspect_bytes`, never pulls a second chunk from an indefinite stream such as SSE, and replays everything captured so the client receives the response unchanged. End-to-end tests prove a matching body rule now escalates to a ban and a streaming response arrives intact while being scanned.
- **Behaviour (three cases, stated exactly)** - `behavior_scan_response_body` defaults to False, so nothing changes for anyone who does not opt in. A body-based `return_pattern` rule with the flag off now raises `ValueError` at config or decorator construction naming the offending pattern, instead of shipping a rule that can never match. Only a deliberate opt-in on an adapter without the protocol (any fastapi-guard before this release) skips the rule, with guard-core's throttled could-not-evaluate warning naming it.
- **Compatibility (lockstep, do not soften)** - Upgrading guard-core to 3.12.0 without upgrading fastapi-guard to 7.6.0 silently drops every `return_pattern` body rule even with `behavior_scan_response_body=True` explicitly set. Upgrading fastapi-guard first is safe in either order: with older guard-core the new adapter methods are simply never called. guard-core stays an unconstrained dependency in `pyproject.toml` per this project's policy, so fresh installs already resolve 3.12.0; this release is what makes that pairing whole.
- **Compatibility (guard-core 3.12.0 breaking changes surfaced here)** - Nine `SecurityConfig` collection fields are now immutable (`whitelist`, `blacklist`, `trusted_proxies` as tuples; `enabled_detection_categories`, `muted_event_types`, `muted_metric_types`, `muted_check_logs`, `block_cloud_providers` as frozensets; `threat_ban_config` as a read-only mapping), and `global_behavior_rules` is a tuple: in-place mutation raises, so reassign a whole new value instead; construction still accepts plain lists and sets. `block_cloud_providers` now raises `ValueError` on an unrecognized provider name instead of silently dropping it. fastapi-guard's own code, tests and examples were audited for both: nothing mutated these fields in place, and every reconfiguration already reassigns.
- **Fixed** - **Both example apps crashed at import under guard-core 3.12.0, and their `pattern="404"` rules had never fired.** `examples/simple_app` and `examples/advanced_app` used `return_monitor(pattern="404")` meaning HTTP status 404; under 3.12.0 that raises at decoration time, and as written the rule was also dead, a body substring match against a body that was never readable. Both now use `status:404`, which is what they always meant. The behavioral decorator tests opt into `behavior_scan_response_body=True`, which makes them the first end-to-end exercise of body matching this repository has ever run.
- **Internal** - **The geo_ip_handler inert-config warning test asserted a warning guard-core 3.12.0 removed.** The warning was undecidable at the `SecurityConfig` layer (route-level country lists, geo rate limits and dynamic rules all consume the handler without the global lists being set), so 3.12.0 removed it. The test file now asserts the warning's absence at both construction and middleware creation, renamed to `test_geo_ip_handler_no_inert_warning.py` to describe the behavior it locks in.
- **Documentation** - Field types updated for the immutable collections, the `exclude_paths` description corrected (detection and behavioral tracking are skipped on excluded paths; IP bans, blacklists, blocked countries, blocked cloud providers and rate limits are still enforced there), and every behavioral-rules example annotated with the flag and version requirement so no documented snippet raises under guard-core 3.12.0.

___

v7.5.1 (2026-08-09)
-------------------

Advanced example now initializes at startup, a lint gate that could not fail, and corrected agent buffer guidance (v7.5.1)
--------------------------------------------------------------------------------------------------------------------------

- **Fixed** - **The advanced example never initialized its middleware at startup.** `examples/advanced_app/app/main.py` wired a plain `lifespan` that only logged, so `SecurityMiddleware.initialize()` ran lazily on the first request instead of at startup. Its sibling `examples/simple_app/main.py` used `make_lifespan` correctly, so the two examples disagreed about the supported startup path and the advanced one modelled the pattern the tutorial steers readers away from. It now uses `make_lifespan` while keeping its own lifespan body intact.
- **Fixed** - **Both examples now show what the pipeline actually built.** The middleware's `Security pipeline initialized with N checks: [...] (M skipped)` startup line is surfaced in both example apps, so a reader can see the effect of guard-core 3.10.0's config-derived pipeline on their own configuration rather than inferring it.
- **Fixed** - **`make lint` could not fail.** The target chained its tools with `;` instead of `&&`, so only the last command determined the exit code. `ruff check` and `mypy` failures were discarded, which is how a real import-sorting violation reached CI while `make lint` reported success locally. The chain now uses `&&`. Separately `ruff format` ran without `--check`, so it rewrote files in place and returned 0 unconditionally; that step could never fail either. It now runs with `--check`, and the formatting drift this exposed across 46 Markdown files is applied in its own commit.
- **Fixed** - **`agent_buffer_size` guidance was wrong and contradicted the in-wheel skill.** The documentation recommended `5000` for production traffic and cited a batch limit of 10,000 events and 5,000 metrics. Read against guard-agent's source, the 256 KiB request body cap is real and enforced server side, no client side batch count limit exists anywhere in the agent, and the quoted figure has no basis in code. The skill already said to keep the default of 100. Every surface now agrees on 100 and explains the body size cap that motivates it.
- **Documentation** - **Accuracy sweep against 7.5.0.** Roughly 20 further corrections across the README, `docs/`, the in-wheel skill and the example apps, each verified against the code as shipped rather than against neighbouring documentation. This covers the logger namespace diagram, which omitted three loggers that genuinely fire, `SecurityConfig` default values quoted in prose, the `detection_exclusion` signature, and links to files that do not exist at the paths given. Every fenced Python example in the touched files was executed rather than eyeballed.

___

v7.5.0 (2026-08-05)
-------------------

Pipeline composition support and quality-gate repairs (v7.5.0)
----------------------------------------------------------------

- **Added** - **Route configuration is visible when the pipeline is built.** guard-core 3.10.0 derives the security pipeline from the effective configuration, skipping checks that configuration can never trigger. Six of those checks are driven purely by per-route decorators, and guard-core can only skip them when it can enumerate the registered route configuration. `SecurityMiddleware` now adopts `app.state.guard_decorator` before `initialize()` builds the pipeline, so an application that registers its decorator handler that way gets the smaller pipeline instead of the conservative full one. Applications that call `set_decorator_handler` were already covered. When no decorator handler can be found the route configuration is treated as unknown and every route-driven check is kept, so this path can only lose the optimization, never the protection. The pipeline log line now reports how many checks were skipped alongside the ones that ran.
- **Fixed** - **Requests carrying a non-mapping ASGI scope no longer corrupt pipeline construction.** The decorator adoption guards every attribute access and verifies the scope is a mapping, so a request-like object without a real `scope` leaves the decorator handler unset rather than propagating a bogus value into pipeline construction.
- **Internal** - **The dead-code gate was doing nothing.** Both `vulture` invocations in the `vulture` Makefile target were commented out, so `make quality` reported success without scanning anything. The target now runs, and the one real finding it surfaced is fixed.
- **Internal** - **A warning filter was masking 30 live deprecation warnings.** `pyproject.toml` carried a `filterwarnings` entry suppressing guard-core's `ipinfo_token is deprecated` warning, which 24 call sites in the middleware tests were triggering. The entry is removed and the call sites no longer pass the deprecated field. The suite runs warning-free with no filters configured at all.
- **Internal** - **Test suite warning cleanup.** Fixtures that wired a `geo_ip_handler` without any country rule tripped guard-core's validator warning on every use; the dead wiring is removed. The example application's seven Pydantic models migrated from class-based `Config` to `model_config = ConfigDict(...)`. `httpx2` is added to the dev dependencies, which is what starlette's test client now expects.
- **Internal** - **`test_rate_limiting_with_redis` was failing about half the time.** Each request stalled roughly 3.3 seconds on a live geo-IP lookup that could not initialize, and three such requests took about as long as the test's own 10 second rate-limit window, so whether the third request still fell inside the window was decided by network latency. The test no longer exercises the geo path it never asserted on, and now runs in well under a second.
- **Internal** - **`guard/middleware.py` maintainability.** The decorator adoption lives in `guard/_decorator_adoption.py` so the middleware module stays at rank A against the declared `mi_min = "A"`.
- **Compatibility (shared-state registry key)** - `guard._middleware_state.get_state` and `register_state` gained a `decorator` parameter, and the registry key changed from `id(config)` to `(id(config), id(guard_decorator))`. The module is underscore-private, so this is not public API, but anything reaching into it directly still breaks. The key changed because two `SecurityMiddleware` instances can share one `SecurityConfig` while decorating different routes now that the pipeline is derived from route configuration; keying on `id(config)` alone would let the second app adopt the first app's already-eliminated pipeline by reference and silently skip checks its own routes need.
- **Compatibility (guard-core dependency)** - `guard-core` stays an unconstrained dependency in `pyproject.toml` per this project's policy. Installed against guard-core 3.9.0, this release's adapter code only calls `build_default_pipeline()` and reads the `guard_decorator` attribute, both of which already existed there, so it degrades to the previous conservative full-pipeline behavior rather than crashing. The test suite does require guard-core 3.10.0, since `tests/test_middleware/test_pipeline_composition.py` asserts the smaller, decorator-driven pipeline by check name, so guard-core 3.10.0 must be published before this suite runs in CI; this is a CI ordering constraint, not a runtime crash risk for installed applications.
- **Compatibility (dev dependencies)** - `httpx2` is added to `[project.optional-dependencies].dev`, which is what starlette's `TestClient` now expects.

___

v7.4.1 (2026-08-03)
-------------------

Library-skills skill and internal gate debt cleanup (v7.4.1)
------------------------------------------------------------

- **Added** - **Library-skills skill** embedded at `guard/.agents/skills/fastapi-guard/SKILL.md` so `uvx library-skills --claude` discovers fastapi-guard from the installed wheel.
- **Fixed** - **Docs**: Corrected the NiceGUI startup example in `first-steps.md` and `security-middleware.md`. `app.on_startup` takes the handler as an argument (it is not a decorator), so `@app.on_startup` was wrong/misleading (it returns `None` and rebinds the function). The examples now call `app.on_startup(_warm_up_guard)` and note the hook runs once at app boot from NiceGUI's FastAPI lifespan (not per client; per client is `app.on_connect`), with `guard_startup`'s idempotency keeping the once-at-boot goal safe under reload/restart.
- **Internal** - Cleared pre-existing mypy gate debt in tests and examples and excluded scratch dirs from mypy. No behavior change.

___

v7.4.0 (2026-07-31)
-------------------

Initialization-status probe and a closed lifespan-discoverability trap (v7.4.0)
--------------------------------------------------------------------------------

- **Added** — `SecurityMiddleware.get_initialization_status()` reports cloud-provider and geo-IP warmup readiness. It delegates to guard-core's `HandlerInitializer.get_initialization_status()` and JSON-encodes the result, so `datetime` values serialize as ISO 8601 strings. `guard.status.add_status_route(app, path="/_guard/status")` is an opt-in helper that wires it as a `GET` route — nothing is registered unless you call it. Cheap enough to back a Kubernetes/ALB warmup probe. Requires `guard-core>=3.8.0`.
- **Added** — `guard.lifespan.guard_startup(app)`: a public, awaitable warm-up entry point for host frameworks — NiceGUI, Chainlit, Gradio, and similar — that own the ASGI `lifespan` slot internally and only expose their own startup-hook registration API (e.g. NiceGUI's `app.on_startup`). It performs exactly what `guard_lifespan` does on entry (locate the middleware, adopt or build warm state, initialize, mark initialized, register state) by reusing the same private helper rather than duplicating it, and shares its idempotency guarantee: the shared-state registry is keyed by `id(config)`, so a second call finds the state already registered and adopts it instead of re-initializing or re-fetching anything.
- **Fixed** — `SecurityMiddleware` now warns when it initializes lazily on the first request while `SecurityConfig.lazy_init=False` is set. That combination previously failed silently: `lazy_init` only governs guard-core's own Redis-gated background warmup, not whether `SecurityMiddleware.initialize()` itself runs at ASGI startup versus on the first request — that timing is controlled entirely by whether `guard_lifespan` / `make_lifespan` / `guard_startup` is wired in. A user who set `lazy_init=False` and wired none of them reasonably expected boot-time initialization and instead hit a confusing "uninitialized" state on their first request. The new warning names the mismatch explicitly; initialization behavior is unchanged.
- **Changed (example)** — `examples/simple_app/main.py` now wires `make_lifespan`, composed with the example's own startup/shutdown logging (previously registered via `@app.on_event`, which had gone silently inert now that Starlette no longer reads `on_startup`/`on_shutdown` once an explicit `lifespan` is set), and demonstrates `add_status_route`. The flagship example now shows the fully-correct eager-init-plus-readiness-probe setup instead of leaving it to be inferred from docs alone.
- **Docs** — The boot-time-initialization precondition — previously one sentence at the bottom of `first-steps.md` and never mentioned next to `lazy_init` itself, which wasn't documented in `security-config.md` at all — is now a prominent warning admonition, cross-linked from `lazy_init`'s (new) entry in the configuration reference. Both docs now present all three initialization-wiring tiers in order: `guard_lifespan` (you own the app), `make_lifespan` (you have a lifespan to compose with), `guard_startup` (the host framework owns the lifespan slot).
- **Compatibility** — Additive only. No change to middleware dispatch ordering or to what is blocked vs. allowed by any existing check — locked in by a new regression test covering a representative blocked and allowed request. `get_initialization_status` / `add_status_route` require `guard-core>=3.8.0` (unreleased at time of writing; tracked at rennf93/guard-core#50). `guard-core` remains an unconstrained dependency in `pyproject.toml` per this project's convention, so installing against an older guard-core only raises `AttributeError` when those two new entry points are actually called — not at import time, and not for any of this release's other changes.

___

v7.3.1 (2026-07-29)
-------------------

Per-route checks now resolve through unbounded mount and router nesting (v7.3.1)
--------------------------------------------------------------------------------

- **Security** — Fixes [GHSA-f2vm-w8gq-h378](https://github.com/rennf93/fastapi-guard/security/advisories/GHSA-f2vm-w8gq-h378) (CWE-287, per-route authentication bypass, CVSS 7.4). `SecurityMiddleware._match_route()` capped its recursive walk of the route tree at a hardcoded depth of 8 and silently gave up beyond it, so an endpoint mounted 9 or more `Mount` levels deep never resolved, `request.state.guard_route_id` was never set, and guard-core's route-config resolver returned `None` — which every per-route check reads as "no policy to enforce". An endpoint protected by `@require_auth` was served to any unauthenticated client, and by the same path so were `@rate_limit`, `@require_headers`, `@require_referrer`, `@custom_validation`, `@time_window`, per-route IP restrictions, and request size / content-type limits. The arbitrary depth cap is replaced by cycle detection over the descent chain — the condition it was approximating — so nesting is now unbounded while a self-nesting router still terminates.
- **Security** — The same bypass reached a second, more common topology: routers nested two or more levels deep via `include_router`, previously recorded in 7.2.2 as "deeply-nested prefixed routers remain a known limitation". FastAPI's `_IncludedRouter` keeps its sub-routes un-prefixed and applies the combined include prefix only in `effective_candidates()`, so descending into `original_router.routes` compared a request path like `/r0/r1/secret` against a route registered as `/r1/secret` and matched nothing. Resolution now descends through `effective_candidates()` where available — falling back to the previous attribute walk on FastAPI versions without it — and unwraps the `_EffectiveRouteContext` proxies it yields. Per-route decorators consequently fire at any include depth, and also on `Mount`s and plain Starlette `Route`s registered on an included router, which `include_router(router, prefix=...)` over `router.mount(...)` had likewise left unresolved.
- **Added** — `SecurityMiddleware` now reports a failed route match by setting `request.state.guard_route_unresolved`, which is the fail-open half of the advisory: `get_route_config()` returns `None` both when a route carries no per-route config and when resolution failed, and every per-route check collapses those two states into "nothing to enforce". Skipping checks on an undecorated route is correct and unchanged; skipping them because resolution failed is not. With guard-core >= 3.7.0 and `SecurityConfig.route_resolution_strict=True`, an unresolved request is logged, emits a `route_unresolved` event, and is blocked with `500` instead of running the pipeline with no per-route config. It defaults to `False` because a failed match is indistinguishable from a request the app does not route, so enabling it also turns unserved paths into `500`s rather than `404`s. Older guard-core ignores the new state attribute.
- **Performance** — Traversal is bounded by marking each route and sub-route collection as visited per request scope rather than by a fixed depth, so a graph reaching the same collection along many paths is walked once instead of exponentially often. An app with two overlapping sibling mounts per level resolves a non-matching 24-level path in 0.2 ms, against 99 s for a depth-capped walk without the marking. The one graph shape that still recurses without bound manufactures fresh sub-route objects on every access, which is not constructible through public FastAPI or Starlette APIs; it raises `RecursionError` and surfaces as `500` rather than as a silently unchecked route.
- **Fixed** — `SecurityConfig.global_behavior_rules` never ran. `_process_response()` passed `process_behavioral_rules` to guard-core's response factory but never `process_global_behavioral_rules`, and the factory only evaluates global rules when that callback is supplied, so the branch was unreachable on every request. A rule such as `return_pattern` with `threshold=2` and `action="ban"` served six matching requests without ever banning. The callback is now wired to `BehavioralProcessor.process_global_return_rules`. Global rules additionally need guard-core >= 3.7.0, which fixes the companion defect that left the behavioural tracker unresolved on decorator-only setups and made `usage_monitor` and `return_monitor` inert too.
- **Tests** — Route resolution and end-to-end `@require_auth` enforcement are now covered at 12 nested `Mount` levels and at 12 nested prefixed routers, plus a `Mount` inside a prefixed included router, alongside the existing self-nesting-router termination test. The global-rule callback is asserted at the call site; the end-to-end banning behaviour it enables is covered in guard-core, since it cannot fire until 3.7.0 ships.

___

v7.3.0 (2026-07-15)
-------------------

Security pipeline assembly delegated to guard-core's check factory (v7.3.0)
---------------------------------------------------------------------------------

- **Changed** — The security pipeline is now assembled by guard-core's `build_default_pipeline()`. New guard-core checks are picked up automatically; the middleware no longer hand-lists check classes.
- **Compatibility (behavior change from guard-core 3.5.0)** — Global IP whitelist/blacklist and country rules now apply on routes carrying per-route decorator config; previously any decorated route silently bypassed every global IP and country rule. A client outside a configured global `whitelist` now receives `403` on decorated routes that previously served it. A route-level `@ip_whitelist` now grants access only, not trust: the matched request is still rate-limited, user-agent-filtered, cloud-provider-checked, attack-scanned, and country-checked, while global `whitelist` membership still confers full trust. The IP and country aspects are evaluated independently — a route `@ip_whitelist` match does not bypass country rules; only a route `@whitelist_countries` match overrides the global country gate. See the guard-core 3.5.0 changelog for the full description and migration guidance.
- **Tests** — The decorator test suite now exercises the rate-limiting, user-agent, and suspicious-activity decorators through the enforced security pipeline using a non-whitelisted client, with explicit coverage for the new decorated-route `403` behavior and for a route `@ip_whitelist` client still being rate-limited. Previously these tests sent requests from a globally-whitelisted address, so the security pipeline short-circuited and the decorator logic was never exercised.
- **Requires** — `guard-core>=3.5.0` (declared as unconstrained `guard-core` in pyproject; documented here for upgrade guidance). The pipeline factory (`build_default_pipeline`) and the decorated-route IP/country enforcement this release relies on ship in guard-core 3.5.0; installing against an older guard-core fails at middleware initialization with an `ImportError`.

___

v7.2.2 (2026-07-01)
-------------------

include_router route resolution now descends the FastAPI wrapper (v7.2.2)
------------------------------------------------------------------------

- **Fixed** — Per-route decorator config now resolves on `include_router` routes under FastAPI >= 0.115. 7.2.1 resolved routes with `route.matches()` but stopped at FastAPI's `_IncludedRouter` wrapper: its `matches()` returns `Match.FULL` with an empty child-scope and the real routes nested inside. Older FastAPI flattened included routers onto the app (so `matches()` found the leaves directly and CI passed), but newer FastAPI keeps them inside the wrapper — so 7.2.1 resolved nothing there and every per-route decorator (`rate_limit`, `max_request_size`, `content_type_filter`, `custom_validation`, `detection_exclusion`, `suspicious_detection`, `usage_monitor`, `honeypot_detection`, behavioral rules) was still inert. Resolution now descends recursively into matched sub-routers/mounts (`.routes`, `original_router.routes`, `.app.routes`), so per-route config fires on `include_router` and path-parameter routes. Direct routes and single-level `include_router` (prefixed or not) are covered; deeply-nested prefixed routers remain a known limitation of the wrapper's child-scope handling. Supersedes the incomplete 7.2.1 fix.

___

v7.2.1 (2026-07-01)
-------------------

Per-route config resolves on parameterised and included routes (v7.2.1)
-----------------------------------------------------------------------

- **Fixed** — Per-route decorator config now resolves on routes with path parameters and routes added via `include_router`. `SecurityMiddleware` is a `BaseHTTPMiddleware`, so it runs before the router and `scope["route"]` is unset; it resolved the active route by exact-path string comparison (`r.path == request.url.path`), which never matches a templated path like `/items/{id}`. As a result every per-route decorator (`rate_limit`, `max_request_size`, `content_type_filter`, `custom_validation`, `detection_exclusion`, `suspicious_detection`, behavioral rules, …) silently did nothing on parameterised or router-included routes. Route resolution now replicates Starlette's own `route.matches(scope)` matching, so per-route config fires on those routes too. Static, non-parameterised routes are unaffected.

___

v7.2.0 (2026-06-23)
-------------------

Agent-setup clarity, single-source exports, and adoption docs (v7.2.0)
----------------------------------------------------------------------

- **Added** — Clear, actionable agent-setup errors + opt-in strict mode. When `enable_agent=True` but the `guard-agent` package is missing, the middleware now surfaces `pip install fastapi-guard[agent]` instead of the misleading "invalid config / check `agent_api_key`" path — it catches `AgentPackageNotInstalledError` from guard-core 3.2.0. Agent-init failures degrade gracefully by default (they log, set `agent_degraded` — exposed via `agent_stats` — and fire the `on_error(stage="agent_init")` hook), while the new `SecurityConfig.agent_strict=True` re-raises for fail-fast deployments.
- **Added** — `fastapi-guard[agent]` optional-dependency extra that installs `guard-agent`, so the agent is opt-in rather than a hidden requirement.
- **Changed** — `guard.__all__` is now single-sourced from `guard_core.__all__` plus fastapi-guard's two locals (`SecurityMiddleware`, `__version__`) instead of being hand-duplicated, so the two export lists can no longer silently drift; a test enforces it.
- **Docs** — New "Passive to Active" migration guide: a reversible observe → preview → verify → enforce → rollback path for turning enforcement on, including a read-only "would-block preview" to size the blast radius before flipping `passive_mode`.
- **Docs** — Behavioral decorators now document the required wiring step. The behavioral tutorial and the `simple_app` example include `app.state.guard_decorator = guard_deco` — the step that makes decorator rules actually fire — plus how to verify violations (`decorator_violation` event) and trial safely with `passive_mode`.
- **Compatibility** — Requires guard-core 3.2.0 or newer (the agent-setup clarity relies on `AgentPackageNotInstalledError`, introduced there). The test suite filters guard-core's new `ipinfo_*` `DeprecationWarning`.

___

v7.1.1 (2026-05-26)
-------------------

guard-core 3.1.0 compatibility: cloud-provider set typing + lazy-init test alignment (v7.1.1)
---------------------------------------------------------------------------------------------

- **Fixed** — `SecurityMiddleware.refresh_cloud_ip_ranges()` now normalizes `SecurityConfig.block_cloud_providers` to `set[str]` before forwarding it to guard-core's `cloud_handler.refresh_async()` / `refresh()`. guard-core 3.1.0 narrowed the field's type to `set[Literal["AWS", "GCP", "Azure"]]`; because `set` is invariant, forwarding it directly raised a mypy `arg-type` error against the handler's `set[str]` parameter. Runtime behavior is unchanged — the values were always those provider strings.
- **Fixed (tests)** — The Redis-initialization test that asserts eager cloud-IP and geo-IP handler wiring now sets `SecurityConfig(lazy_init=False)` explicitly. guard-core 3.1.0 changed the `lazy_init` default from `False` to `True`, which defers those `initialize_redis()` calls into a background task; the test exercises the eager path and so must opt into it.
- **Compatibility** — Patch-level; no public API change. v7.1.0 declared `guard-core>=3.1.0`, but its CI run completed minutes before guard-core 3.1.0 was published, so two 3.1.0-only changes — `block_cloud_providers` literal typing and the `lazy_init=True` default — went unexercised until now. v7.1.1 brings the adapter source and test suite into line with the guard-core 3.1.0 it already targets. Note: under guard-core's `lazy_init=True` default, cloud-IP and geo-IP caches warm in the background after startup rather than blocking initialization — wire `guard_lifespan` (v7.1.0) or set `SecurityConfig(lazy_init=False)` to restore eager warm-up.
- **Requires** — `guard-core>=3.1.0` (declared as unconstrained `guard-core` in pyproject; documented here for upgrade guidance).

___

v7.1.0 (2026-05-15)
-------------------

ASGI-lifespan-driven warm-up and Starlette body-typing fix (v7.1.0)
-------------------------------------------------------------------

- **Added** — `guard.lifespan.guard_lifespan` and `guard.lifespan.make_lifespan(existing_lifespan=None)` helpers. Wire `app = FastAPI(lifespan=guard_lifespan)` to fully initialize guard-core's security pipeline, agent integrations, OTEL/Logfire providers, Redis connection, and cloud-IP cache during ASGI lifespan startup. First request hits a pre-warmed middleware with zero re-initialization. Backed by a per-`SecurityConfig` shared-state registry (`guard._middleware_state`) — Starlette's middleware-stack architecture would normally create a separate `SecurityMiddleware` instance for the request path (causing duplicate `composite_handler.start()` calls and leaked agent/OTEL worker tasks), but the registry guarantees per-config init runs exactly once and the live request-handling instance adopts the spawned instance's pipeline/agent/event-bus by reference.
- **Added** — `SecurityMiddleware.mark_initialized()`: public method used by the lifespan helpers to record that initialization has completed, so external callers no longer have to reach into the underscore-prefixed `_initialized` attribute.
- **Changed** — `SecurityMiddleware` now backs its per-instance state (security pipeline, composite agent handler, event bus, metrics collector, response factory, validator, bypass handler, behavioral processor) via a module-level `guard._middleware_state` registry keyed by `id(config)`. Multiple `SecurityMiddleware` instances sharing the same `SecurityConfig` (e.g. a lifespan-spawned instance + Starlette's live request-handling instance, or a sub-app mounted middleware) now share state by reference instead of each rebuilding their own copy. Eliminates the `OTEL TracerProvider already set` warning that previously fired on first request when `enable_otel=True` or `enable_logfire=True` and `guard_lifespan` was wired in.
- **Documented** — `SecurityMiddleware.initialize()` is now formally part of the public API for advanced lifespan integration patterns. Without lifespan wiring, fastapi-guard still works correctly: initialization happens lazily on the first request via the existing fallback path.
- **Fixed** — `StarletteGuardResponse.body` now always returns `bytes` instead of leaking `bytes | memoryview` from the underlying Starlette `Response`, silencing a pre-existing mypy invariance error and ensuring downstream code that calls `len()` / slicing on the body sees consistent types.
- **Requires** — `guard-core>=3.1.0` (declared as unconstrained `guard-core` in pyproject; documented here for upgrade guidance). v3.1.0 brings NOSCRIPT-aware rate limiting, `lazy_init=True` as the default, the `cloud_ip_store` factory protocol, and country-code/cloud-provider normalization in decorators and dynamic rules.

___

v7.0.0 (2026-04-29)
-------------------

Fail-secure by default (upstream), agent-stats surface, version reporting (v7.0.0)
----------------------------------------------------------------------------------

- **Breaking (upstream)** — `SecurityConfig.fail_secure` now defaults to `True` (inherited from `guard-core >= 3.0.0`). When any security check raises an unhandled exception, the request is now blocked with HTTP 500 instead of logging and falling through. Bugs in checks that previously slipped past as silent fail-open responses now surface immediately. Restore the old behavior on deployments that depend on it via `SecurityConfig(fail_secure=False)`. Recommended migration: keep the new default, surface any check exceptions in your monitoring, and fix them — the previous default could mask serious bugs. The fastapi-guard major bump tracks this upstream change so deployments see a clear signal.
- **Added** — `SecurityMiddleware.agent_stats` read-only `@property` returning the agent's telemetry buffer state. Returns `{"enabled": False}` when no agent is wired; otherwise returns `{"enabled": True, **agent_handler.get_stats()}` exposing `events_dropped`, `metrics_dropped`, `circuit_breaker_state`, and other agent counters. No caching — fresh on each call. Lets app teams build health endpoints that surface agent-side drops and circuit-breaker trips without scraping the agent directly.
- **Added** — `from guard import __version__` — package version is now exported via `importlib.metadata.version("fastapi-guard")` with a `"0.0.0+unknown"` fallback if the package is not installed (development from source). Pairs with `guard-core >= 3.0.0`'s `SecurityConfig.agent_guard_version` so application code can wire the fastapi-guard version through to the agent for SaaS-side telemetry attribution: `SecurityConfig(agent_guard_version=__version__)`.
- **Compatibility** — `SecurityMiddleware.agent_stats` is purely additive; no existing API was changed. `__version__` was previously absent; reading it before this release returned `None` via missing-attribute fallback in some integrations.

___

v6.0.0 (2026-04-26)
--------------------

CORS routed through SecurityMiddleware via guard_core.cors_handler (v6.0.0)
----------------------------------------------------------------------------

- **Breaking** — Removed `SecurityMiddleware.configure_cors(app, config)`. CORS is now handled inside `SecurityMiddleware`; configure via `SecurityConfig.cors_*` fields and the middleware activates CORS automatically. The security pipeline now runs against `OPTIONS` preflight requests — previously the external Starlette `CORSMiddleware` short-circuited preflights ahead of `SecurityMiddleware`, allowing banned IPs and rate-limited clients to preflight freely.
- **Migration** — Before: `app.add_middleware(SecurityMiddleware, config=config)` + `SecurityMiddleware.configure_cors(app, config)`. After: `app.add_middleware(SecurityMiddleware, config=config)` only.
- **Fixed** — Cross-origin preflight requests to passthrough paths (e.g. `exclude_paths=["/health"]`) now receive a valid CORS response. Preflight handling runs ahead of the passthrough/bypass short-circuit so the browser permission check works for excluded paths.
- **Fixed** — Cross-origin GETs to passthrough/bypass paths now carry CORS headers on their responses, matching the previous outer-CORSMiddleware semantics that the `configure_cors` design provided.
- **Fixed** — `cloud_handler.refresh()` was being called without `await` — the coroutine was never awaited, meaning cloud-IP refreshes silently never completed in production. Surfaced and fixed at root after removing the `[[tool.mypy.overrides]] follow_imports = "skip"` block that had been hiding the type error.
- **Internal** — Removed all three `[[tool.mypy.overrides]]` suppression blocks (`pydantic.*`, `redis.*`, `guard_core.*`). All three packages ship `py.typed` in their current versions; the `follow_imports = "skip"` settings had been masking real type errors. Stripped `[tool.uv.sources] guard-core` local-path block from committed pyproject.toml. pyproject.toml dependency on guard-core remains unconstrained.
- **Requires** — `guard-core>=2.2.0` (declared as unconstrained `guard-core` in pyproject; documented here for upgrade guidance).

___

v5.2.0 (2026-04-25)
-------------------

guard-core 2.0.0 adoption (v5.2.0)
----------------------------------

- **Changed** — `SecurityMiddleware.suspicious_request_counts` is now typed `dict[str, dict[str, int]]` (per-IP, per-category nested counters) to match the guard-core 2.0.0 protocol shape. The middleware itself does not mutate this attribute directly — guard-core's `SuspiciousActivityCheck` owns the writes — so no behavior change is visible to user code that did not reach into this internal field.
- **Changed** — Test fixtures that previously mocked `guard_core.utils.detect_penetration_attempt` and `guard_core.core.checks.implementations.suspicious_activity.detect_penetration_patterns` with raw `(bool, str)` tuples now return `DetectionResult(is_threat=..., trigger_info=...)`, mirroring the new return type from guard-core's detection engine.
- **Compat** — Requires guard-core 2.0.0 or newer. The major-bump in guard-core changes `suspicious_request_counts` to a per-category nested dict, replaces `detect_penetration_attempt` / `detect_penetration_patterns` 2-tuple returns with `DetectionResult`, and migrates the cloud-IP cache namespace. fastapi-guard's middleware was updated to match the new protocol shape; user code that didn't reach into those internals continues to work unchanged.
- **User-visible impact** — None for users on the public API (`SecurityConfig`, `SecurityMiddleware`, `SecurityDecorator`, the 20+ per-route decorators). Users who imported guard-core internals directly (e.g. `detect_penetration_attempt`, `detect_penetration_patterns`, or the raw `suspicious_request_counts` shape) must adapt to the new return type / nested dict — see the guard-core 2.0.0 release notes for the migration guide.

___

v5.1.1 (2026-04-24)
-------------------

Integration fixes for OTel + enrichment pipeline (v5.1.1)
---------------------------------------------------------

- **Fixed** — `SecurityMiddleware.initialize()` is now invoked on the first request via a `_ensure_initialized()` asyncio-lock guard inside `dispatch()`. Previously the method existed but was never called, so `HandlerInitializer.initialize_agent_integrations()` never ran and the composite handler stayed `None`. Without this fix, no OTel span or Logfire log was ever emitted regardless of config.
- **Fixed** — After composite construction, `self.agent_handler` is rebound from the bare `guard-agent` client to the composite. Downstream callers that receive `middleware.agent_handler` (most notably `guard_core.utils.extract_client_ip → send_agent_event`) now route through the composite, so enrichment and OTel see every event instead of the ~13% that happened to go through the pipeline directly.
- **Fixed** — `BehavioralContext` now receives `handler_initializer.behavior_tracker`, matching the guard-core 1.2.1 wiring. This closes the last architectural gap so `guard.behavior.recent_event_count` populates end-to-end when `enable_enrichment=True`.
- **Added** — `tests/test_middleware/test_middleware_lifecycle.py` — regression tests that pin lazy initialization semantics (runs once on first dispatch, no-op when telemetry disabled, single-init under concurrent dispatch) and confirm `behavioral_processor.context.behavior_tracker` is the same object owned by `handler_initializer`.
- **Requires** — `guard-core>=1.2.1` for the matching OTLP endpoint normalization and `BehaviorTracker` wiring fixes. Install the latest with `uv add fastapi-guard` or `pip install -U fastapi-guard guard-core`.
- **User-visible impact** — Users with `enable_otel=True`, `enable_logfire=True`, or `enable_enrichment=True` previously saw silent drops: the middleware never ran `initialize()`, so the composite handler was never constructed and nothing reached OTel, Logfire, or the enricher. After this release the composite is built on the first request and all downstream agent callers receive it, so every event flows through telemetry and enrichment as configured. No `SecurityConfig` changes required.

___

v5.1.0 (2026-04-24)
-------------------

Telemetry pipeline wiring fix (v5.1.0)
--------------------------------------

Adopts guard-core 1.1.0 and fixes a middleware wiring bug that prevented OpenTelemetry, Logfire, and event/metric/check-log muting from seeing anything emitted by the request-path security pipeline.

- **Fixed** — `SecurityMiddleware` previously constructed `SecurityEventBus(agent_handler, ...)` and `MetricsCollector(agent_handler, ...)` directly inside `__init__`, using the bare `guard_agent` handler (or `None`). `HandlerInitializer.initialize_agent_integrations()` then built a `CompositeAgentHandler` that no code path ever reached, because the event bus / metrics collector were frozen on the bare handler from `__init__`. As a result, every event emitted through the request pipeline (`SecurityEventBus.send_middleware_event`) and every request metric bypassed OTel, Logfire, and the configured `muted_event_types` / `muted_metric_types` filter. This release rewires the middleware to call `HandlerInitializer.build_event_bus()` and `.build_metrics_collector()` after `initialize_agent_integrations()` completes, so the composite handler is on the hot path. The dependent contexts (`ResponseContext`, `ValidationContext`, `BypassContext`, `BehavioralContext`) are rebuilt at the same point so they bind to the post-init event bus.
- **Added** — `tests/test_middleware/test_middleware_wiring.py` — four regression tests that pin `middleware.event_bus.agent_handler` and `middleware.metrics_collector.agent_handler` to `CompositeAgentHandler` after `middleware.initialize()` when OTel or Logfire is enabled, and confirm all dependent contexts reference the post-init event bus.
- **Dependencies** — `guard-core>=1.1.0,<2.0.0` (was unpinned).
- **User-visible impact** — Users already setting `enable_otel=True` or `enable_logfire=True` on `SecurityConfig` were previously getting handler-path events only (ip_banned, rate_limited from `ip_ban_manager` / `rate_limit_handler`, etc.) — but never pipeline-path events (`penetration_attempt`, `authentication_failed`, `user_agent_blocked`, `https_enforced`, etc.) or request metrics (`guard.request.duration`, `guard.request.count`, `guard.error.count`). After this release, every event and every metric flows through the composite, which means OTel spans, Logfire logs, and all mute fields (`muted_event_types`, `muted_metric_types`, `muted_check_logs`) work as documented. No `SecurityConfig` changes required; existing configurations produce strictly more telemetry, not less.

___

v5.0.0 (2026-03-26)
-------------------

Major Release (v5.0.0)
------------

- **Guard-Core migration**: FastAPI Guard is now a thin adapter over [guard-core](https://github.com/rennf93/guard-core), the framework-agnostic security engine. All security logic (17 checks, 8 handlers, detection engine) lives in guard-core; this package provides only the FastAPI/Starlette integration layer.
- **Zero breaking changes to public API**: All existing imports (`from guard import SecurityConfig`, `from guard.middleware import SecurityMiddleware`, etc.) continue to work exactly as before.
- **Shared engine across frameworks**: The same security engine now powers [flaskapi-guard](https://github.com/rennf93/flaskapi-guard) and [djangoapi-guard](https://github.com/rennf93/djangoapi-guard), ensuring consistent security behavior across all three frameworks.

___

v4.4.1 (2026-03-16)
-------------------

Bug Fixes (v4.4.1)
------------

- **Per-endpoint rate limit check**: Fixed rate limit check to properly evaluate endpoint-specific rate limits. Previously, the rate limit check was only evaluating global rate limits.

___

v4.4.0 (2026-03-14)
-------------------

New Features (v4.4.0)
------------

- **Configurable cloud IP refresh interval**: New `cloud_ip_refresh_interval` config field (default: 3600s, valid range: 60-86400s) allows tuning how often cloud provider IP ranges are refreshed. The interval is propagated to Redis TTL for cache consistency.
- **Change detection logging for cloud IP refreshes**: When cloud IP ranges are refreshed, additions and removals are logged per provider (e.g., `+12 added, -3 removed`), providing visibility into IP range mutations.
- **Context-aware detection engine**: Suspicious pattern rules are now tagged with applicable input contexts (`query_param`, `url_path`, `header`, `request_body`). Patterns are only evaluated against relevant input sources, reducing false positives.
- **Structured JSON logging**: New `log_format="json"` config option outputs logs as structured JSON (`{"timestamp": "...", "level": "...", "logger": "...", "message": "..."}`), enabling integration with log aggregation systems (ELK, Datadog, CloudWatch).
- **Per-provider `last_updated` timestamps**: `CloudManager` now tracks when each provider's IP ranges were last refreshed via `cloud_handler.last_updated["AWS"]`, returning `datetime | None`.

___

v4.3.1 (2026-03-11)
-------------------

Bug Fixes (v4.3.1)
------------

- **Geographic rate limit check**: Fixed geo-based rate limiting by implementing the missing `_check_geo_rate_limit` method in `RateLimitCheck`. Previously, geo rate limits configured via the `@security.geo_rate_limit` decorator were stored but never enforced. The rate limit pipeline now correctly evaluates geo-based limits at priority 3 (after endpoint-specific and route-specific limits).
- **Geo rate limit decorator**: Fixed `RateLimitingMixin.geo_rate_limit` decorator to store limits on `route_config.geo_rate_limits` instead of incorrectly serializing them into `required_headers`.
- **IPInfo country whitelist fail-closed**: When `whitelist_countries` is configured and a client's country cannot be determined, `IPInfoManager.check_country_access` now correctly blocks the request (fail-closed) instead of allowing it through.

Enhancements (v4.3.1)
------------

- **Timezone-aware time windows**: Time window restrictions now support configurable timezones via the `timezone` field in `time_restrictions`. Uses `ZoneInfo` for proper timezone handling with a safe fallback to UTC for invalid timezone strings.
- **Geo rate limit RouteConfig support**: Added `geo_rate_limits` attribute to `RouteConfig` for proper type-safe storage of geographic rate limit configurations.

___

v4.3.0 (2026-03-10)
-------------------

Bug Fixes (v4.3.0)
------------

- **Whitelisted IP bypass**: Whitelisted IPs now correctly bypass rate limiting, cloud provider blocking, user agent filtering, and suspicious activity detection checks. Previously, the whitelist flag was only checked during IP security validation but not propagated to downstream security checks.

Enhancements (v4.3.0)
------------

- **Version bump helper**: Added `make bump-version VERSION=x.y.z` command and `.github/scripts/bump_version.py` script to automate version updates across all project files (pyproject.toml, .mike.yml, versions.json, docs/index.md, changelogs).

CI/CD (v4.3.0)
------------

- **Docker actions**: Bumped `docker/login-action` from 3 to 4 and `docker/setup-compose-action` from 1 to 2.
- **Pre-commit**: Simplified pre-commit checks in scheduled lint workflow and disabled semgrep in pre-commit configuration.

___

v4.2.2 (2025-12-02)
-------------------

Support/Compatibility (v4.2.2)
------------

- **Python 3.14**: Added support for Python 3.14.

___

v4.2.1 (2025-11-05)
-------------------

Bug Fixes (v4.2.1)
------------

- **IPInfo redirect URLs**: IPInfo API sometimes responds with 302 code, and by not handling the redirect, the database would not be downloaded. Now, `IPInfoManager` class follows redirects.

___

v4.2.0 (2025-10-16)
-------------------

Internal Refactoring (No Breaking Changes) (v4.2.0)
------------

**Major architectural transformation** completed (v4.2.0):

- **Middleware Refactoring**: Broke down `middleware.py` from monolithic file into modular architecture.
- **Maintainability Improvement**: Improved from MI 0.00 (Rank C - "unmaintainable") to MI 54.51 (Rank A)
- **Complexity Reduction**: Average complexity reduced from ~15 to 2.35 (84.3% improvement)
- **Code Reduction**: middleware.py reduced by 77.4% through modular extraction
- **Test Coverage**: Maintained at 100% throughout refactoring
- **Zero Breaking Changes**: All public APIs remain unchanged

New Internal Architecture (`guard/core/`) (v4.2.0)
------------

There are now 9 specialized modules (all achieving Rank A maintainability, MI 56-82):

1. **`checks/`** - Security check implementations using Chain of Responsibility pattern
   - `SecurityCheck` base class
   - `SecurityCheckPipeline` for orchestration
   - 17 check implementations in `implementations/`

2. **`events/`** - Event system for middleware actions
   - `SecurityEventBus` for centralized event dispatching
   - `MetricsCollector` for request metrics collection

3. **`initialization/`** - Handler initialization logic
   - `HandlerInitializer` for centralized Redis, Agent, and handler setup

4. **`responses/`** - Response handling
   - `ErrorResponseFactory` for response creation and processing
   - `ResponseContext` for dependency injection

5. **`routing/`** - Routing and decorator resolution
   - `RouteConfigResolver` for route configuration
   - `RoutingContext` for dependency injection

6. **`validation/`** - Request validation utilities
   - `RequestValidator` for HTTPS checks, proxy validation, time windows
   - `ValidationContext` for dependency injection

7. **`bypass/`** - Security bypass handling
   - `BypassHandler` for passthrough and bypass logic
   - `BypassContext` for dependency injection

8. **`behavioral/`** - Behavioral rule processing
   - `BehavioralProcessor` for usage and return rules
   - `BehavioralContext` for dependency injection

Benefits (v4.2.0)
------------

- **Faster Development**: Faster feature additions
- **Better Testability**: Each module independently testable
- **Improved Performance**: Better code organization and caching
- **Maintainable Codebase**: Single Responsibility Principle applied throughout

Migration Notes (v4.2.0)
------------

**For Users**: No migration needed - all existing code works unchanged
**For Contributors**: See `ARCHITECTURE_CHANGES.md` for detailed module breakdown

**Important**: The `guard/core/*` modules are internal implementation details. Always import from public API.

___

v4.1.2 (2025-09-12)
-------------------

Enhancements (v4.1.2)
------------

- Added dynamic rule updated event type.

___

v4.1.0 (2025-09-07)
-------------------

New Features (v4.1.0)
------------

- **Enhanced Security Headers**: Added 5 new default security headers following OWASP best practices:
  - `X-Permitted-Cross-Domain-Policies: none` - Restricts Adobe Flash cross-domain access
  - `X-Download-Options: noopen` - Prevents file download execution in Internet Explorer
  - `Cross-Origin-Embedder-Policy: require-corp` - Controls cross-origin resource embedding
  - `Cross-Origin-Opener-Policy: same-origin` - Controls cross-origin window interactions
  - `Cross-Origin-Resource-Policy: same-origin` - Controls cross-origin resource access
- **Security Validation Framework**: Comprehensive input validation for all header configurations
- **Advanced CORS Validation**: Runtime validation and logging for CORS misconfiguration attempts
- **Security Event Logging**: Enhanced logging for security violations and configuration warnings

Security Fixes (v4.1.0)
---------

- Fixed header injection vulnerability in SecurityHeadersManager - preventing injection attacks via newlines and control characters
- Enhanced CORS security - wildcard origins (`*`) now properly blocked when credentials are enabled to prevent security bypass
- Implemented thread-safe singleton pattern with double-checked locking to prevent race conditions in multi-threaded environments
- Secure cache key generation using SHA256 hashing to prevent cache poisoning attacks
- Added CSP unsafe directive validation - warnings for `'unsafe-inline'` and `'unsafe-eval'` directives
- HSTS preload validation - ensures preload requirements (max_age ≥ 31536000, includeSubDomains) are met
- Input validation for all header values - sanitization of control characters and length limits (8192 bytes)

Improvements (v4.1.0)
------------

- **Performance**: Optimized cache key generation using SHA256 with path normalization
- **Reliability**: Thread-safe singleton implementation prevents multiple instances in concurrent environments
- **Security**: All header values now validated against injection attacks, newlines, and excessive length
- **Monitoring**: Improved security event logging for better observability and debugging
- **Documentation**: Updated security headers documentation with new features and best practices

___

v4.0.3 (2025-08-09)
-------------------

Bug Fixes (v4.0.3)
---------

- **Logging Configuration Fix**: Fixed `custom_log_file` configuration being ignored - file logging now works correctly
- **Logging Behavior**: File logging is now truly optional - only enabled when `custom_log_file` is explicitly set
- **Namespace Consistency**: All FastAPI Guard components now use consistent `fastapi_guard.*` logger namespace hierarchy
  - Root logger: `fastapi_guard`
  - Handlers: `fastapi_guard.handlers.{component}`
  - Decorators: `fastapi_guard.decorators.{component}`
  - Detection Engine: `fastapi_guard.detection_engine`
- **Console Output**: Console logging is now always enabled for visibility, regardless of file logging configuration
- **Passive Mode Enhancement**: Fixed passive mode to properly log without blocking for all security checks including rate limiting, suspicious patterns, and decorator violations

Improvements (v4.0.3)
------------

- **Logger Isolation**: FastAPI Guard logs are now properly isolated from user application logs
- **Test Compatibility**: Logger propagation enabled for better test framework integration
- **Documentation**: Updated all logging documentation to reflect actual behavior
- **Passive Mode Consistency**: All security checks now properly respect passive mode - logging violations without blocking requests
- **Enhanced Logging Context**: Improved log messages with better context for passive mode operations, including trigger information for suspicious patterns

___

v4.0.2 (2025-08-07)
-------------------

New Features (v4.0.2)
------------

- **Sus Patterns Handler Overhaul**: Complete redesign of the suspicious patterns detection system with modular architecture
  - **Pattern Compiler**: Safe regex execution with configurable timeouts to prevent ReDoS attacks
  - **Content Preprocessor**: Heuristic content truncation that searches the trimmed bytes for known attack-pattern matches and preserves them in the retained slice
  - **Semantic Analyzer**: Heuristic-based detection using TF-IDF and n-gram analysis for obfuscated attacks
  - **Performance Monitor**: Tracks regex pattern execution times and warns when an individual pattern exceeds the configured slow-pattern threshold (slow-pattern monitoring, not request-anomaly detection)
  - **Enhanced Detection API**: Rich detection results with threat scores, detailed threat information, and performance metrics
  - **Lazy Component Initialization**: Detection components only load when explicitly configured
  - **Comprehensive Configuration**: New `detection_*` configuration options for fine-tuning all components

Improvements (v4.0.2)
------------

- **Pattern Matching Performance**: Timeout protection prevents slow patterns from blocking requests
- **Detection Accuracy**: Multi-layered approach combines regex patterns with semantic analysis
- **Memory Efficiency**: Configurable limits on content length and pattern tracking
- **Observability**: Detailed performance metrics and slow pattern identification
- **Backward Compatibility**: Legacy `detect_pattern_match` API maintained for smooth migration
- **Agent Integration**: Automatic telemetry for pattern detection events and performance metrics

___

v3.0.2 (2025-07-22)
-------------------

Security Fixes (v3.0.2)
------------

- **IMPORTANT**: Enhanced ReDoS prevention - Prevent regex bypass due to length limitations on pattern regex. (GHSA-rrf6-pxg8-684g)
- **CVE ID**: CVE-2025-54365
- Added timeout to avoid catastrophical backtracking and/or regex bypass by length limitation expression.
- Added new `regex_timeout` parameter to `SecurityConfig` to allow for custom timeout for regex pattern matching.

___

v3.0.1 (2025-07-07)
-------------------

Security Fixes (v3.0.1)
------------

- **IMPORTANT**: Prevented ReDoS (Regular Expression Denial of Service - CWE-1333) attacks by replacing unbounded regex quantifiers with bounded ones. (GHSA-j47q-rc62-w448)
- **CVE ID**: CVE-2025-53539

___

v3.0.0 (2025-06-21)
-------------------

New Features (v3.0.0)
------------

- **Security Decorators**: Added comprehensive route-level security decorator system
  - `SecurityDecorator` class combining all security capabilities
  - Access control decorators for IP filtering, geographic restrictions, and cloud provider blocking
  - Authentication decorators for HTTPS enforcement, auth requirements, and API key validation
  - Rate limiting decorators with custom limits and geographic rate limiting
  - Threshold-based behavior decorators: per-IP request counting, response-pattern matching, and suspicious-frequency triggers (deterministic threshold matching, not learning-based)
  - Content filtering decorators for content type validation, size limits, and user agent blocking
  - Advanced decorators for time windows, suspicious detection, and honeypot detection
  - Route-specific configuration that can override global middleware settings
  - Seamless integration with existing SecurityMiddleware
- **Behavior Manager**: Added threshold-based behavior tracking and monitoring
  - `BehaviorTracker` for tracking per-IP and per-endpoint request patterns
  - `BehaviorRule` for defining threshold-based behavior rules
  - Support for endpoint usage tracking, return pattern matching, and frequency-threshold detection
  - Multiple pattern formats including JSON paths, regex, and status codes
  - Automated actions (ban, alert, log, throttle) when configured thresholds are exceeded
  - Redis integration for distributed behavior-counter storage

___

v2.1.3 (2025-06-18)
-------------------

Bug Fixes (v2.1.3)
---------

- Fixed IPv6 address support throughout the project - PR [#51](https://github.com/rennf93/fastapi-guard/pull/51) - Issue [#50](https://github.com/rennf93/fastapi-guard/issues/50)

___

v2.1.2 (2025-05-26)
-------------------

Improvements (v2.1.2)
------------

- Switched from Poetry to uv for package management

___

v2.1.1 (2025-05-08)
-------------------

Bug Fixes (v2.1.1)
---------

- Fixed `custom_response_modifier` implementation.

___

v2.1.0 (2025-05-08)
-------------------

Improvements (v2.1.0)
------------

- **Rate Limiting**: Replaced fixed window rate limiting with true sliding window algorithm
- Added atomic Redis Lua script for distributed rate limiting
- Improved timestamp tracking for more accurate request counting
- Fixed edge cases in rate limiting that could cause unexpected 429 errors

___

v2.0.0 (2025-05-05)
-------------------

Security Fixes (v2.0.0)
--------------

- **IMPORTANT**: Fixed Remote Header Injection vulnerability via X-Forwarded-For manipulation (GHSA-77q8-qmj7-x7pp)
- **CVE ID**: CVE-2025-46814
- Added secure client IP extraction with trusted proxy validation
- Added new configuration parameters for proxy security:
  - `trusted_proxies`: List of trusted proxy IPs or CIDR ranges
  - `trusted_proxy_depth`: Configurable proxy chain depth
  - `trust_x_forwarded_proto`: Option to trust X-Forwarded-Proto header

New Features (v2.0.0)
------------

- IPInfo is now completely optional, you can implement your own `GeoIPHandler`
- Added protocol-based design for customizable geographical IP handling
- Introduced `GeoIPHandler` protocol allowing custom implementations
- Separated protocol definitions into dedicated modules

Improvements (v2.0.0)
------------

- Deprecated `ipinfo_token` and `ipinfo_db_path` in favor of `geo_ip_handler`
- Improved type safety and code readability
- Added runtime type checking for custom GeoIP handlers

___

v1.5.0 (2025-05-01)
-------------------

Improvements (v1.5.0)
------------

- IpInfo token is now only required when using country filtering or cloud blocking
- Performance: Selective loading of IP geolocation database and cloud IP ranges
- Only download/process IP geolocation data when country filtering is configured
- Only fetch cloud provider IP ranges when cloud blocking is enabled
- Reduced startup time and memory usage when not using all security features

___

v1.4.0 (2025-04-30)
-------------------

New Features (v1.4.0)
------------

- Added configurable logging levels for normal and suspicious requests
- Enhanced log_activity function to support all logging levels
- Added ability to completely disable request logging

Improvements (v1.4.0)
------------

- Improved performance by allowing complete disabling of normal request logging
- Better log level control for different environments (dev/prod)

___

v1.3.2 (2025-04-27)
-------------------

New Features (v1.3.2)
------------

- Created an interactive [FastAPI Guard Playground](https://playground.fastapi-guard.com)
- Added `passive_mode` option to log suspicious activity without blocking requests
- Enhanced `detect_penetration_attempt` function to return trigger information

___

v1.2.2 (2025-04-07)
-------------------

Improvements (v1.2.2)
------------

- Added an empty `py.typed`
- Fixed the `package_data` configuration in `setup.py`
- Added `mypy` configuration to `pyproject.toml`
- Added `MANIFEST.in`

___

v1.2.1 (2025-04-05)
-------------------

New Features (v1.2.1)
------------

- Added new pattern management methods to `SusPatternsManager`:
  - `get_default_patterns()` and `get_custom_patterns()` for separate pattern access
  - `get_default_compiled_patterns()` and `get_custom_compiled_patterns()` for separate compiled pattern access
- Enhanced `remove_pattern()` method to return success/failure status

Improvements (v1.2.1)
------------

- Fixed issue with default pattern removal in `SusPatternsManager`
- Improved pattern separation between default and custom patterns

___

v1.2.0 (2025-04-04)
-------------------

New Features (v1.2.0)
------------

- Added dedicated `RateLimitManager` for improved rate limiting functionality
- TTLCache-based in-memory rate limiting still available
- Extended Redis support for distributed rate limiting

Improvements (v1.2.0)
------------

- Fixed rate limiting logic to properly handle rate limiting
- Standardized Singleton pattern across all handlers
- Added new `keys`and `delete_pattern` methods to `RedisManager` for easy key/pattern retrieval/cleanup

___

v1.1.0 (2025-03-21)
-------------------

New Features (v1.1.0)
------------

- Added proper typing throughout the codebase
- Added custom Docker container for example app
- Added better Docker Compose support

Improvements (v1.1.0)
------------

- Fixed multiple typing issues across test files
- Improved documentation for Docker container usage
- Enhanced serialization of Redis data

___

v1.0.0 (2025-02-19)
-------------------

New Features (v1.0.0)
------------

- Added Redis integration for distributed state management

Improvements (v1.0.0)
------------

- Improved tests & testing coverage (100% coverage)

___

v0.4.0 (2025-02-16)
-------------------

New Features (v0.4.0)
------------

- Added `db_path` parameter to `IPInfoManager` for custom database locations

Improvements (v0.4.0)
------------

- Improved IPInfo database handling with local caching

Bug Fixes (v0.3.4)
---------

- Fixed Azure IP ranges download by adding proper User-Agent headers ([#19](https://github.com/rennf93/fastapi-guard/pull/19))
- Fixed cloud provider validation logic to properly filter invalid entries
- Resolved test coverage gaps on all test files

___

v0.3.4 (2025-01-26)
-------------------

Bug Fixes (v0.3.3)
---------

- Fixed issue with accepted `Headers` on `Swagger UI` access/requests.

___

v0.3.3 (2024-12-14)
-------------------

Bug Fixes (v0.3.2)
---------

- Fixed package structure to properly include all required modules
- Resolved import issues with handlers package
- Improved package installation reliability
