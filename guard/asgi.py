"""Pure-ASGI variant of the security middleware.

`PureASGISecurityMiddleware` runs the same request-screening pipeline as
`SecurityMiddleware` (initialization, CORS preflight, path exclusions, IP
extraction, ban lists, rate limiting, user-agent blocking, penetration
detection, behavioral usage rules) without inheriting from Starlette's
`BaseHTTPMiddleware`.

Why it exists: `BaseHTTPMiddleware` wraps the downstream app in an anyio
task group whose cancel scope cancels in-flight downstream awaits (database
calls, long LLM streams) when a client disconnects mid-request. Framework
projects that ban `BaseHTTPMiddleware` for exactly this reason (open-webui
is one) can mount this variant instead and keep the same guard behavior.

Response-side differences from `SecurityMiddleware`:

- Security headers and CORS response headers are injected directly on the
  `http.response.start` message; responses stream through unbuffered.
- Decorator-driven response rules (return patterns) and
  `custom_response_modifier` need a materialized `Response` object and are
  only applied by the `BaseHTTPMiddleware`-based middleware.

The downstream app receives a replaying receive channel, so both guard and
the application can read the request body.
"""

import time
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Response
from guard_core.exceptions import GuardRedisError
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig
from guard_core.utils import extract_client_ip
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from guard.adapters import StarletteGuardRequest, wrap_call_next
from guard.middleware import SecurityMiddleware

_BOOL_TRUE = frozenset({"1", "true", "yes", "on"})


class _BodyCachingReceive:
    """Receive wrapper that caches request-body chunks for replay.

    Guard needs the body for penetration and custom-request checks; the
    downstream application still expects to read it afterwards. Chunks are
    buffered on the first pass and replayed to the app in order.
    """

    def __init__(self, receive: Receive) -> None:
        self._receive = receive
        self._cached: list[Message] = []
        self._body_done = False

    async def __call__(self) -> Message:
        message = await self._receive()
        if message["type"] == "http.request":
            self._cached.append(message)
            if not message.get("more_body", False):
                self._body_done = True
        return message

    def replay(self) -> Receive:
        """Return a receive callable that yields the cached body, then
        continues streaming from the original receive (disconnect waits)."""
        messages = list(self._cached)
        index = {"i": 0}
        inner = self._receive

        async def replay_receive() -> Message:
            i = index["i"]
            if i < len(messages):
                index["i"] = i + 1
                return messages[i]
            return await inner()

        return replay_receive


class _HeaderInjectingSend:
    """Send wrapper that merges security and CORS headers into the response
    start message, leaving the body stream untouched."""

    def __init__(
        self,
        send: Send,
        *,
        engine: SecurityMiddleware,
        request: Request,
    ) -> None:
        self._send = send
        self._engine = engine
        self._request = request
        self.status_code: int | None = None

    async def __call__(self, message: Message) -> None:
        if message["type"] == "http.response.start":
            self.status_code = message["status"]
            headers: dict[bytes, bytes] = {
                key: value for key, value in message["headers"]
            }
            extra = await security_headers_manager.get_headers(
                request_path=self._request.url.path, config=self._engine.config
            )
            for key, value in extra.items():
                headers.setdefault(key.encode("latin-1"), value.encode("latin-1"))
            if self._engine._cors_handler is not None:
                cors = self._engine._cors_handler.build_response_headers(
                    self._request.headers
                )
                for key, value in cors.items():
                    headers.setdefault(key.encode("latin-1"), value.encode("latin-1"))
            message = {**message, "headers": list(headers.items())}
        await self._send(message)


class PureASGISecurityMiddleware:
    """Pure-ASGI security middleware sharing the pipeline of
    `SecurityMiddleware`.

    Mount it like the classic middleware::

        app.add_middleware(PureASGISecurityMiddleware, config=config)

    The class is disabled-by-default at the embedding layer the same way
    the classic one is: construct it only when the operator enabled the
    integration. WebSocket and lifespan scopes pass through untouched
    (wrap websocket endpoints with `guard.websocket.make_guard_websocket`
    for socket-level checks).
    """

    def __init__(self, app: ASGIApp, *, config: SecurityConfig) -> None:
        self.app = app
        self.config = config
        # The classic middleware instance is used as the engine: its
        # constructor builds the pipeline, handlers, rate limiter, event bus
        # and CORS handler, and its screening helpers operate on plain
        # Request objects, so none of that machinery is duplicated here.
        self._engine = SecurityMiddleware(_NullApp(), config=config)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        caching_receive = _BodyCachingReceive(receive)
        request = Request(scope, receive=caching_receive)
        wrapped_send = _HeaderInjectingSend(send, engine=self._engine, request=request)
        start_time = time.time()
        await self._screen(request, caching_receive, wrapped_send, scope, start_time)

    async def _screen(  # noqa: PLR0915
        self,
        request: Request,
        caching_receive: _BodyCachingReceive,
        wrapped_send: _HeaderInjectingSend,
        scope: Scope,
        start_time: float,
    ) -> None:
        engine = self._engine
        try:
            await engine._ensure_initialized(request)
        except GuardRedisError as e:
            engine.logger.error("Redis unavailable during initialization: %s", e)
            response = await engine._redis_unavailable_response()
            await self._send_response(response, request, wrapped_send._send)
            return

        guard_request = StarletteGuardRequest(request)
        engine._populate_guard_state(guard_request, request)

        preflight = await engine._handle_preflight(request, guard_request)
        if preflight is not None:
            await self._send_response(preflight, request, wrapped_send._send)
            return

        call_next = self._build_call_next(scope, caching_receive, wrapped_send)
        passthrough = await engine._handle_passthrough(
            request, guard_request, wrap_call_next(call_next, request)
        )
        if passthrough is not None:
            await self._send_response(passthrough, request, wrapped_send._send)
            return

        client_ip = await extract_client_ip(
            guard_request, engine.config, engine.agent_handler
        )
        route_config = engine.route_resolver.get_route_config(guard_request)

        bypass = await engine._handle_security_bypass(
            request,
            guard_request,
            wrap_call_next(call_next, request),
            route_config,
        )
        if bypass is not None:
            await self._send_response(bypass, request, wrapped_send._send)
            return

        blocked = await engine._handle_pipeline_block(request, guard_request)
        if blocked is not None:
            await self._send_response(blocked, request, wrapped_send._send)
            return

        if route_config and route_config.behavior_rules and client_ip:
            await engine.behavioral_processor.process_usage_rules(
                guard_request, client_ip, route_config
            )

        await self._call_downstream(
            scope, caching_receive.replay(), wrapped_send, start_time
        )

    def _build_call_next(
        self,
        scope: Scope,
        caching_receive: _BodyCachingReceive,
        wrapped_send: _HeaderInjectingSend,
    ) -> Callable[[Request], Awaitable[Response]]:
        """Buffered downstream call for the bypass/passthrough helpers, which
        expect a materialized `Response`. Only bypassed routes take this
        path; the regular flow streams instead."""

        async def call_next(request: Request) -> Response:
            captured: dict[str, Any] = {"status": 500, "headers": [], "body": b""}

            async def capturing_send(message: Message) -> None:
                if message["type"] == "http.response.start":
                    captured["status"] = message["status"]
                    captured["headers"] = list(message["headers"])
                elif message["type"] == "http.response.body":  # pragma: no branch
                    captured["body"] += message.get("body", b"")

            await self._call_downstream(
                scope, caching_receive.replay(), capturing_send, time.time()
            )
            return Response(
                status_code=captured["status"],
                headers=dict(
                    (key.decode("latin-1"), value.decode("latin-1"))
                    for key, value in captured["headers"]
                ),
                content=captured["body"],
            )

        return call_next

    async def _call_downstream(
        self,
        scope: Scope,
        receive: Receive,
        send: Send | _HeaderInjectingSend,
        start_time: float,
    ) -> None:
        await self.app(scope, receive, send)
        self._engine.logger.debug(
            "Request processed in %.4fs", time.time() - start_time
        )

    async def _send_response(
        self, response: Response, request: Request, send: Send
    ) -> None:
        """Send a guard-generated blocking response, with CORS headers
        applied the same way the classic dispatch applies them."""
        if self._engine._cors_handler is not None:
            cors_headers = self._engine._cors_handler.build_response_headers(
                request.headers
            )
            for key, value in cors_headers.items():
                response.headers.setdefault(key, value)
        body = getattr(response, "body", b"") or b""
        await send(
            {
                "type": "http.response.start",
                "status": response.status_code,
                "headers": list(response.raw_headers),
            }
        )
        await send({"type": "http.response.body", "body": body})


class _NullApp:
    """Placeholder downstream for the engine instance; never called because
    only the screening helpers of the engine are used."""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        raise RuntimeError("PureASGISecurityMiddleware engine must not be called")
