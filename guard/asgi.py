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
- Per-request metrics (request count, response time, error rate) are
  emitted once the downstream app finishes the response. Response time is
  measured until the response starts, the same as the classic middleware.
- Behavior return rules (route and global) run once the downstream app has
  sent the last body chunk. `status:` patterns read the response start
  message; body patterns (with `behavior_scan_response_body`) read a bounded
  prefix of the streamed body, never the whole body.
- On bypassed routes the downstream response is handed to guard-core as a
  streaming `Response` (never buffered), so `custom_response_modifier` runs
  there as it does in the classic middleware. On the normal path
  `custom_response_modifier` needs a materialized `Response` object and is
  only applied by the `BaseHTTPMiddleware`-based middleware.

The downstream app receives a replaying receive channel, so both guard and
the application can read the request body.
"""

import asyncio
import time
from collections.abc import AsyncGenerator
from typing import Any

from fastapi import Response
from guard_core.exceptions import GuardRedisError
from guard_core.handlers.behavior_handler import config_to_rule
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig
from guard_core.utils import extract_client_ip
from starlette.requests import Request
from starlette.responses import StreamingResponse
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


class _CapturedResponse:
    """Read-only view of a streamed response for behavior return rules."""

    def __init__(
        self, status_code: int, headers: dict[str, str], body_prefix: bytes
    ) -> None:
        self._status_code = status_code
        self._headers = headers
        self._body_prefix = body_prefix

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def headers(self) -> dict[str, str]:
        return self._headers

    @property
    def body(self) -> bytes | None:
        return None

    async def read_body_prefix(self, max_bytes: int) -> bytes:
        return self._body_prefix[:max_bytes]


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
        self.started_at: float | None = None
        self.app_headers: dict[str, str] = {}
        self.body_prefix = b""

    async def __call__(self, message: Message) -> None:
        if message["type"] == "http.response.start":
            self.status_code = message["status"]
            self.started_at = time.time()
            self.app_headers = {
                key.decode("latin-1"): value.decode("latin-1")
                for key, value in message["headers"]
            }
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
        elif message["type"] == "http.response.body":
            self._keep_body_prefix(message.get("body", b""))
        await self._send(message)

    def _keep_body_prefix(self, chunk: bytes) -> None:
        config = self._engine.config
        if not config.behavior_scan_response_body:
            return
        room = config.behavior_max_response_body_inspect_bytes - len(self.body_prefix)
        if room > 0:
            self.body_prefix += chunk[:room]


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

    async def _screen(
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

        downstream: _InlineDownstream | _StreamedDownstream
        if engine.config.custom_response_modifier is None:
            downstream = _InlineDownstream(
                self, scope, caching_receive, request, wrapped_send._send
            )
        else:
            downstream = _StreamedDownstream(self, scope, caching_receive)
        try:
            await self._screen_after_preflight(
                request,
                guard_request,
                caching_receive,
                wrapped_send,
                scope,
                start_time,
                downstream,
            )
        finally:
            await downstream.close()

    async def _screen_after_preflight(
        self,
        request: Request,
        guard_request: StarletteGuardRequest,
        caching_receive: _BodyCachingReceive,
        wrapped_send: _HeaderInjectingSend,
        scope: Scope,
        start_time: float,
        downstream: "_InlineDownstream | _StreamedDownstream",
    ) -> None:
        engine = self._engine
        call_next = wrap_call_next(downstream.call_next, request)
        passthrough = await engine._handle_passthrough(
            request, guard_request, call_next
        )
        if passthrough is not None:
            await self._send_downstream_response(
                passthrough, request, wrapped_send._send, downstream
            )
            return

        client_ip = await extract_client_ip(
            guard_request, engine.config, engine.agent_handler
        )
        route_config = engine.route_resolver.get_route_config(guard_request)

        bypass = await engine._handle_security_bypass(
            request, guard_request, call_next, route_config
        )
        if bypass is not None:
            await self._send_downstream_response(
                bypass, request, wrapped_send._send, downstream
            )
            return

        blocked = await engine._handle_pipeline_block(request, guard_request)
        if blocked is not None:
            await self._send_response(blocked, request, wrapped_send._send)
            return

        throttled = await engine._apply_usage_rules(
            request, guard_request, client_ip, route_config
        )
        if throttled is not None:
            await self._send_response(throttled, request, wrapped_send._send)
            return

        await self._call_downstream(
            scope, caching_receive.replay(), wrapped_send, start_time
        )
        await self._run_behavior_return_rules(
            guard_request, client_ip, route_config, wrapped_send
        )
        await self._record_metrics(guard_request, wrapped_send, start_time)

    async def _run_behavior_return_rules(
        self,
        guard_request: StarletteGuardRequest,
        client_ip: str | None,
        route_config: Any,
        wrapped_send: _HeaderInjectingSend,
    ) -> None:
        if wrapped_send.status_code is None or not client_ip:
            return
        engine = self._engine
        response = _CapturedResponse(
            wrapped_send.status_code,
            wrapped_send.app_headers,
            wrapped_send.body_prefix,
        )
        if route_config and route_config.behavior_rules:
            await engine.behavioral_processor.process_return_rules(
                guard_request, response, client_ip, route_config
            )
        if engine.config.global_behavior_rules:
            await engine.behavioral_processor.process_global_return_rules(
                guard_request,
                response,
                client_ip,
                [config_to_rule(cfg) for cfg in engine.config.global_behavior_rules],
            )

    async def _record_metrics(
        self,
        guard_request: StarletteGuardRequest,
        wrapped_send: _HeaderInjectingSend,
        start_time: float,
    ) -> None:
        # Collector only: process_response would re-apply headers and CORS.
        # response_time stops at response start, like call_next in classic.
        if wrapped_send.status_code is None or wrapped_send.started_at is None:
            return
        await self._engine.metrics_collector.collect_request_metrics(
            guard_request,
            wrapped_send.started_at - start_time,
            wrapped_send.status_code,
        )

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

    async def _send_downstream_response(
        self,
        response: Response,
        request: Request,
        send: Send,
        downstream: "_InlineDownstream | _StreamedDownstream",
    ) -> None:
        if isinstance(response, _ResponseAlreadySent):
            return
        await self._send_response(response, request, send)
        await downstream.raise_failure_after_response_sent()

    async def _send_response(
        self, response: Response, request: Request, send: Send
    ) -> None:
        """Send a response, with CORS headers applied the same way the
        classic dispatch applies them. A streaming response (the downstream
        app on a bypassed or excluded route) is forwarded chunk by chunk;
        guard-generated responses go out as a single body message."""
        if self._engine._cors_handler is not None:
            cors_headers = self._engine._cors_handler.build_response_headers(
                request.headers
            )
            for key, value in cors_headers.items():
                response.headers.setdefault(key, value)
        await send(
            {
                "type": "http.response.start",
                "status": response.status_code,
                "headers": list(response.raw_headers),
            }
        )
        body_iterator = getattr(response, "body_iterator", None)
        if body_iterator is None:
            body = getattr(response, "body", b"") or b""
            await send({"type": "http.response.body", "body": body})
            return
        async for chunk in body_iterator:
            if not isinstance(chunk, bytes | memoryview):
                chunk = chunk.encode(response.charset)
            await send({"type": "http.response.body", "body": chunk, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})


class _ResponseAlreadySent(Response):
    """Returned by `_InlineDownstream.call_next`: the downstream response
    already went to the client, there is nothing left to send."""


class _InlineDownstream:
    """Bypass `call_next` for the default configuration (no
    `custom_response_modifier`): nothing may touch the response, so the
    downstream app runs right here with a `send` that goes straight to the
    client. No task, no handoff, no per-chunk overhead; an app exception or a
    client disconnect behaves exactly as on the regular path."""

    def __init__(
        self,
        middleware: "PureASGISecurityMiddleware",
        scope: Scope,
        caching_receive: _BodyCachingReceive,
        request: Request,
        send: Send,
    ) -> None:
        self._middleware = middleware
        self._scope = scope
        self._caching_receive = caching_receive
        self._request = request
        self._send = send
        self._response_started = False

    async def call_next(self, request: Request) -> Response:
        await self._middleware._call_downstream(
            self._scope,
            self._caching_receive.replay(),
            self._send_with_cors_headers,
            time.time(),
        )
        if not self._response_started:
            raise RuntimeError("No response returned.")
        return _ResponseAlreadySent()

    async def _send_with_cors_headers(self, message: Message) -> None:
        if message["type"] == "http.response.start":
            self._response_started = True
            message = {**message, "headers": self._headers_with_cors(message)}
        await self._send(message)

    def _headers_with_cors(self, start: Message) -> list[tuple[bytes, bytes]]:
        headers = list(start["headers"])
        cors_handler = self._middleware._engine._cors_handler
        if cors_handler is None:
            return headers
        # Guard's CORS headers replace the app's of the same name, as
        # `_inject_cors_headers` does for the classic bypass response.
        cors = {
            name.encode("latin-1").lower(): value.encode("latin-1")
            for name, value in cors_handler.build_response_headers(
                self._request.headers
            ).items()
        }
        kept = [(name, value) for name, value in headers if name.lower() not in cors]
        return kept + list(cors.items())

    async def raise_failure_after_response_sent(self) -> None:
        return None

    async def close(self) -> None:
        return None


class _StreamedDownstream:
    """Runs the downstream app for the bypass helper and hands its response
    back as a streaming `Response`, following Starlette's
    `BaseHTTPMiddleware.call_next` (starlette/middleware/base.py:97-188): the
    app's `send` waits until the consumer took its message, like the
    zero-buffer memory stream Starlette uses, so at most one chunk is in
    flight. `call_next` returns once `http.response.start` is through (status
    and the raw header list, repeated headers kept).

    One deliberate difference: Starlette runs the app inside an anyio task
    group, whose cancel scope can cancel the app's awaits. Here the app runs
    as a plain asyncio task that nothing cancels: a client disconnect reaches
    it only through its own `receive` (http.disconnect) or, once the consumer
    stops reading, as an OSError on its next `send` (which Starlette's
    StreamingResponse turns into ClientDisconnect). Limit: asyncio only.
    """

    def __init__(
        self,
        middleware: "PureASGISecurityMiddleware",
        scope: Scope,
        caching_receive: _BodyCachingReceive,
    ) -> None:
        self._middleware = middleware
        # The app must stream file bodies through this handoff: the
        # `http.response.pathsend` message carries no body to hand over.
        extensions = scope.get("extensions") or {}
        self._scope = {
            **scope,
            "extensions": {
                name: value
                for name, value in extensions.items()
                if name != "http.response.pathsend"
            },
        }
        self._caching_receive = caching_receive
        self._task: asyncio.Task[None] | None = None
        self._failure: Exception | None = None
        self._body_fully_streamed = False
        self._consumer_gone = False
        # (message, taken) pairs; the app's send awaits `taken`, so the queue
        # never holds more than one. None marks the end of the app's run.
        self._handoff: asyncio.Queue[tuple[Message, asyncio.Future[None]] | None] = (
            asyncio.Queue()
        )

    async def call_next(self, request: Request) -> Response:
        self._task = asyncio.create_task(self._run_downstream())
        message = await self._take_response_start()
        response = StreamingResponse(self._stream_body(), status_code=message["status"])
        response.raw_headers = list(message["headers"])
        return response

    async def _take_response_start(self) -> Message:
        while (message := await self._take_next_message()) is not None:
            if message["type"] == "http.response.start":
                return message
        if self._failure is not None:
            raise self._take_failure()
        raise RuntimeError("No response returned.")

    def _take_failure(self) -> Exception:
        # Handing the exception over (instead of keeping it on self) breaks
        # the cycle self -> exception -> traceback -> frame -> self, which
        # would keep the response and the app's generators alive until the
        # cyclic GC runs.
        failure, self._failure = self._failure, None
        assert failure is not None
        return failure

    async def _take_next_message(self) -> Message | None:
        item = await self._handoff.get()
        if item is None:
            return None
        message, taken = item
        taken.set_result(None)
        return message

    async def _run_downstream(self) -> None:
        try:
            await self._middleware._call_downstream(
                self._scope,
                self._caching_receive.replay(),
                self._send_to_consumer,
                time.time(),
            )
        except Exception as exc:
            self._failure = exc
        finally:
            self._handoff.put_nowait(None)

    async def _send_to_consumer(self, message: Message) -> None:
        if self._consumer_gone:
            raise OSError("response consumer is gone")
        taken: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._handoff.put_nowait((message, taken))
        await taken

    async def _stream_body(self) -> AsyncGenerator[bytes, None]:
        while (message := await self._take_next_message()) is not None:
            if message["type"] != "http.response.body":
                continue
            body = message.get("body", b"")
            if body:
                yield body
            if not message.get("more_body", False):
                break
        self._body_fully_streamed = True

    async def raise_failure_after_response_sent(self) -> None:
        """The app may still run after its last body message (background
        work); wait for it and surface its exception like the classic
        middleware does. A response nobody streamed to its end (a modifier
        replaced it) is released by `close` instead."""
        if self._task is not None and self._body_fully_streamed:
            await self._task
            if self._failure is not None:
                raise self._take_failure()

    async def close(self) -> None:
        """Release the app if nobody consumed its response to the end, then
        wait for its task so none is left pending."""
        self._consumer_gone = True
        while not self._handoff.empty():
            item = self._handoff.get_nowait()
            if item is not None and not item[1].done():
                item[1].set_exception(OSError("response consumer is gone"))
        if self._task is not None:
            await self._task
        self._failure = None


class _NullApp:
    """Placeholder downstream for the engine instance; never called because
    only the screening helpers of the engine are used."""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        raise RuntimeError("PureASGISecurityMiddleware engine must not be called")
