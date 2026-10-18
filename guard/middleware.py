import asyncio
import time
from collections.abc import Awaitable, Callable, Iterator
from typing import TYPE_CHECKING, Any, cast

from fastapi import Request, Response
from fastapi.encoders import jsonable_encoder
from guard_core.core.behavioral import BehavioralContext, BehavioralProcessor
from guard_core.core.bypass import BypassContext, BypassHandler
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.core.checks.route_prefixes import template_route_prefix
from guard_core.core.events import MetricsCollector, SecurityEventBus
from guard_core.core.initialization import HandlerInitializer
from guard_core.core.responses import ErrorResponseFactory, ResponseContext
from guard_core.core.routing import RouteConfigResolver, RoutingContext
from guard_core.core.validation import RequestValidator, ValidationContext
from guard_core.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.exceptions import AgentPackageNotInstalledError, GuardRedisError
from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.handlers.cors_handler import CorsHandler, is_preflight
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig
from guard_core.protocols import AgentHandlerProtocol, GuardResponse
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.utils import (
    extract_client_ip,
    invoke_error_hook,
    setup_custom_logging,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse
from starlette.routing import Match, Mount, get_route_path
from starlette.types import ASGIApp

from guard._response_headers import merge_vary
from guard.adapters import (
    StarletteGuardRequest,
    StarletteResponseFactory,
    unwrap_response,
    wrap_call_next,
)

if TYPE_CHECKING:
    from guard._middleware_state import MiddlewareState


_FULL = (Match.FULL,)
_FULL_OR_PARTIAL = (Match.FULL, Match.PARTIAL)


def _path_params(values: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((name, str(value)) for name, value in values.items()))


def _router_route_prefixes(routes: Any, base: str) -> list[str]:
    prefixes: list[str] = []
    for route in routes:
        path = getattr(route, "path", None)
        if path is None:
            prefixes.append("/")
        elif isinstance(route, Mount):
            mounted = base + path
            prefixes.append(mounted)
            inner = route.routes
            prefixes.extend(
                _router_route_prefixes(inner, mounted) if inner else [mounted + "/"]
            )
        else:
            prefixes.append(template_route_prefix(base + path))
    return prefixes


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, config: SecurityConfig) -> None:
        super().__init__(app)
        self.app = app
        self.config = config
        self.logger = setup_custom_logging(
            config.custom_log_file, log_format=config.log_format
        )
        self.last_cloud_ip_refresh = 0
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self.last_cleanup = time.time()
        self.rate_limit_handler = RateLimitManager(config)
        self.guard_decorator: BaseSecurityDecorator | None = None

        self._configure_security_headers(config)

        self.geo_ip_handler = None
        if config.whitelist_countries or config.blocked_countries:
            self.geo_ip_handler = config.geo_ip_handler

        self.redis_handler = None
        if config.enable_redis:
            from guard_core.handlers.redis_handler import RedisManager

            self.redis_handler = RedisManager(config)

        self.agent_handler: AgentHandlerProtocol | None = None
        self.agent_degraded = False
        if config.enable_agent:
            try:
                agent_config = config.to_agent_config()
                from guard_agent import guard_agent

                self.agent_handler = cast(
                    AgentHandlerProtocol, guard_agent(cast(Any, agent_config))
                )
                self.logger.info("Guard Agent initialized successfully")
            except AgentPackageNotInstalledError as e:
                self._on_agent_init_failed(
                    config,
                    e,
                    "Agent enabled but guard-agent is not installed. "
                    "Install with: pip install fastapi-guard[agent]",
                )
            except Exception as e:
                self._on_agent_init_failed(
                    config, e, f"Failed to initialize Guard Agent: {e}"
                )

        self.security_pipeline: SecurityCheckPipeline | None = None
        self._routing_app: Any = None

        self._guard_response_factory = StarletteResponseFactory()

        self.event_bus = SecurityEventBus(
            self.agent_handler, self.config, self.geo_ip_handler
        )
        self.metrics_collector = MetricsCollector(self.agent_handler, self.config)

        self.handler_initializer = HandlerInitializer(
            config=self.config,
            redis_handler=self.redis_handler,
            agent_handler=self.agent_handler,
            geo_ip_handler=self.geo_ip_handler,
            rate_limit_handler=self.rate_limit_handler,
            guard_decorator=self.guard_decorator,
        )

        routing_context = RoutingContext(
            config=self.config,
            logger=self.logger,
            guard_decorator=self.guard_decorator,
        )
        self.route_resolver = RouteConfigResolver(routing_context)
        self._global_throttle_rules = any(
            rule.action == "throttle" for rule in config.global_behavior_rules
        )

        self._build_event_dependent_contexts()

        self._initialized = False
        self._init_lock = asyncio.Lock()
        self._cors_handler: CorsHandler | None = (
            CorsHandler(config) if config.enable_cors else None
        )

    def _is_initialized(self) -> bool:
        return self._initialized

    def mark_initialized(self) -> None:
        self._initialized = True

    def _warn_if_eager_init_not_honored(self) -> None:
        if self.config.lazy_init:
            return
        self.logger.warning(
            "lazy_init=False was set, but SecurityMiddleware is initializing on "
            "the first request instead of at ASGI startup because no lifespan "
            "hook warmed it. Wire guard.lifespan.guard_lifespan (or "
            "make_lifespan/guard_startup) into the app to get true boot-time "
            "initialization."
        )

    async def _ensure_initialized(self, request: Request | None = None) -> None:
        if self._is_initialized():
            return
        async with self._init_lock:
            if self._is_initialized():
                return

            from guard._decorator_adoption import adopt_app_state_decorator
            from guard._middleware_state import (
                MiddlewareState,
                get_state,
                register_state,
            )

            self.guard_decorator = adopt_app_state_decorator(
                self.guard_decorator, request
            )
            warm = get_state(self.config, self.guard_decorator)
            if warm is not None:
                self._adopt_warm_state(warm)
                self._initialized = True
                return

            self._warn_if_eager_init_not_honored()
            await self.initialize()
            register_state(
                self.config,
                self.guard_decorator,
                MiddlewareState(
                    security_pipeline=self.security_pipeline,
                    composite_handler=self.handler_initializer.composite_handler,
                    event_bus=self.event_bus,
                    metrics_collector=self.metrics_collector,
                    response_factory=self.response_factory,
                    validator=self.validator,
                    bypass_handler=self.bypass_handler,
                    behavioral_processor=self.behavioral_processor,
                    handler_initializer=self.handler_initializer,
                    agent_handler=self.agent_handler,
                ),
            )
            self._initialized = True

    def _adopt_warm_state(self, state: "MiddlewareState") -> None:
        self.security_pipeline = cast(SecurityCheckPipeline, state.security_pipeline)
        self.event_bus = cast(SecurityEventBus, state.event_bus)
        self.metrics_collector = cast(MetricsCollector, state.metrics_collector)
        self.response_factory = cast(ErrorResponseFactory, state.response_factory)
        self.validator = cast(RequestValidator, state.validator)
        self.bypass_handler = cast(BypassHandler, state.bypass_handler)
        self.behavioral_processor = cast(
            BehavioralProcessor, state.behavioral_processor
        )
        self.handler_initializer = cast(HandlerInitializer, state.handler_initializer)
        if state.composite_handler is not None:
            self.agent_handler = cast(AgentHandlerProtocol, state.composite_handler)
        elif state.agent_handler is not None:
            self.agent_handler = cast(AgentHandlerProtocol, state.agent_handler)

    def _build_event_dependent_contexts(self) -> None:
        response_context = ResponseContext(
            config=self.config,
            logger=self.logger,
            metrics_collector=self.metrics_collector,
            agent_handler=self.agent_handler,
            redis_handler=self.redis_handler,
            guard_decorator=self.guard_decorator,
            response_factory=self._guard_response_factory,
        )
        self.response_factory = ErrorResponseFactory(response_context)

        validation_context = ValidationContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
        )
        self.validator = RequestValidator(validation_context)

        bypass_context = BypassContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
            route_resolver=self.route_resolver,
            response_factory=self.response_factory,
            validator=self.validator,
        )
        self.bypass_handler = BypassHandler(bypass_context)

        behavioral_context = BehavioralContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
            guard_decorator=self.guard_decorator,
            behavior_tracker=self.handler_initializer.behavior_tracker,
            middleware=self,
        )
        self.behavioral_processor = BehavioralProcessor(behavioral_context)

    @property
    def guard_response_factory(self) -> StarletteResponseFactory:
        return self._guard_response_factory

    def _on_agent_init_failed(
        self, config: SecurityConfig, exc: Exception, message: str
    ) -> None:
        self.agent_degraded = True
        invoke_error_hook(config.on_error, "agent_init", exc, {})
        if config.agent_strict:
            raise exc
        self.logger.error(message)
        self.logger.warning("Continuing without agent functionality")

    @property
    def agent_stats(self) -> dict[str, Any]:
        if self.agent_handler is None:
            return {"enabled": False, "degraded": self.agent_degraded}
        handler_stats = cast(Any, self.agent_handler).get_stats()
        return {"enabled": True, "degraded": self.agent_degraded, **handler_stats}

    def _build_security_pipeline(self) -> None:
        from guard_core.core.checks import DEFAULT_CHECK_CLASSES, build_default_pipeline

        pipeline = build_default_pipeline(self)
        self.security_pipeline = pipeline
        self.logger.info(
            f"Security pipeline initialized with {len(pipeline)} checks: "
            f"{pipeline.get_check_names()} "
            f"({len(DEFAULT_CHECK_CLASSES) - len(pipeline)} skipped)"
        )

    def _configure_security_headers(self, config: SecurityConfig) -> None:
        if not config.security_headers:
            security_headers_manager.enabled = False
            return

        if not config.security_headers.get("enabled", True):
            security_headers_manager.enabled = False
            return

        security_headers_manager.enabled = True
        headers_config = config.security_headers
        hsts_config = headers_config.get("hsts") or {}

        security_headers_manager.configure(
            enabled=headers_config.get("enabled", True),
            csp=headers_config.get("csp"),
            hsts_max_age=hsts_config.get("max_age"),
            hsts_include_subdomains=hsts_config.get("include_subdomains", True),
            hsts_preload=hsts_config.get("preload", False),
            frame_options=headers_config.get("frame_options", "SAMEORIGIN"),
            content_type_options=headers_config.get("content_type_options", "nosniff"),
            xss_protection=headers_config.get("xss_protection", "1; mode=block"),
            referrer_policy=headers_config.get(
                "referrer_policy", "strict-origin-when-cross-origin"
            ),
            permissions_policy=headers_config.get("permissions_policy", "UNSET"),
            custom_headers=headers_config.get("custom"),
            cors_origins=config.cors_allow_origins if config.enable_cors else None,
            cors_allow_credentials=config.cors_allow_credentials,
            cors_allow_methods=config.cors_allow_methods,
            cors_allow_headers=config.cors_allow_headers,
            override_apps=False,
        )

    def set_decorator_handler(
        self, decorator_handler: BaseSecurityDecorator | None
    ) -> None:
        self.guard_decorator = decorator_handler

    async def _check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        result: bool = await self.validator.check_time_window(time_restrictions)
        return result

    async def _check_route_ip_access(
        self, client_ip: str, route_config: RouteConfig
    ) -> bool | None:
        from guard_core.core.checks.helpers import check_route_ip_access

        result: bool | None = await check_route_ip_access(client_ip, route_config, self)
        return result

    async def _check_user_agent_allowed(
        self, user_agent: str, route_config: RouteConfig | None
    ) -> bool:
        from guard_core.core.checks.helpers import check_user_agent_allowed

        result: bool = await check_user_agent_allowed(
            user_agent, route_config, self.config
        )
        return result

    async def _process_response(
        self,
        request: Request,
        response: Response,
        response_time: float,
        route_config: RouteConfig | None,
    ) -> Response:
        from guard.adapters import StarletteGuardResponse

        guard_request = StarletteGuardRequest(request)
        guard_response = StarletteGuardResponse(response)
        result = await self.response_factory.process_response(
            guard_request,
            guard_response,
            response_time,
            route_config,
            process_behavioral_rules=self.behavioral_processor.process_return_rules,
            process_global_behavioral_rules=(
                self.behavioral_processor.process_global_return_rules
            ),
        )
        return unwrap_response(result)

    def _resolve_route(self, request: Request) -> Any:
        return self._resolve_route_with_params(request.scope)[0]

    def _resolve_route_with_params(self, scope: Any) -> tuple[Any, dict[str, Any]]:
        route = scope.get("route")
        if route:
            return route, scope.get("path_params", {})
        return next(self._matching_routes(scope, _FULL), (None, {}))

    def _matching_routes(
        self, scope: Any, accepted: tuple[Match, ...]
    ) -> Iterator[tuple[Any, dict[str, Any]]]:
        app = scope.get("app")
        routes = getattr(app, "routes", None)
        if not routes:
            return
        redirect_slashes = getattr(
            getattr(app, "router", app), "redirect_slashes", False
        )
        yield from self._match_router(routes, scope, set(), redirect_slashes, accepted)

    def _match_router(
        self,
        routes: Any,
        scope: Any,
        seen: set[Any],
        redirect_slashes: bool,
        accepted: tuple[Match, ...],
    ) -> Iterator[tuple[Any, dict[str, Any]]]:
        # Starlette's router answers a path none of its routes match with a 307 to the
        # same path with the trailing slash toggled, when a route matches there, so that
        # route's decorator config is the one that governs this request. Each router
        # decides with its own redirect_slashes: a mounted app for the paths under its
        # mount, the including app for an included router's routes.
        found = False
        for match in self._match_route(routes, scope, seen, accepted):
            found = True
            yield match
        if found or not redirect_slashes:
            return
        route_path = get_route_path(scope)
        if route_path == "/" or any(
            self._route_match(r, scope)[0] != Match.NONE for r in routes
        ):
            return
        path = scope["path"]
        toggled = path.rstrip("/") if route_path.endswith("/") else f"{path}/"
        yield from self._match_route(routes, {**scope, "path": toggled}, seen, accepted)

    def _match_route(
        self, routes: Any, scope: Any, seen: set[Any], accepted: tuple[Match, ...]
    ) -> Iterator[tuple[Any, dict[str, Any]]]:
        # This middleware is a BaseHTTPMiddleware, so it runs before the router
        # and scope["route"] is unset. Replicate Starlette's matching, descending
        # into sub-routers / mounts (FastAPI's include_router inserts a wrapper
        # route whose real routes are nested inside), so per-route decorator
        # config resolves for path-parameter and include_router routes, not only
        # routes flattened directly onto the app. Each hit is the route plus the
        # path parameters Starlette captured on the way down.
        if not self._first_visit(seen, routes, scope):
            return
        for r in routes:
            match, child = self._route_match(r, scope)
            if match not in accepted:
                continue
            r = self._unwrap_candidate(r)
            params = child.get("path_params", {})
            if getattr(r, "endpoint", None) is not None:
                yield r, params
                continue
            child_scope = {**scope, **child}
            if not self._first_visit(seen, r, child_scope):
                continue
            sub_routes = self._sub_routes(r)
            if not sub_routes:
                yield r, params
            else:
                # A Mount with middleware keeps the mounted app, whose routes these
                # are, in _base_app and the middleware-wrapped one in app.
                mounted = getattr(r, "_base_app", getattr(r, "app", None))
                yield from self._match_router(
                    sub_routes,
                    child_scope,
                    seen,
                    getattr(
                        getattr(mounted, "router", mounted), "redirect_slashes", False
                    ),
                    accepted,
                )

    def _first_visit(self, seen: set[Any], node: Any, scope: Any) -> bool:
        # Replaces a fixed depth cap, which silently abandoned the walk and left
        # deeply nested routes unresolved. Marking the route and its sub-route
        # collection stops mount cycles and keeps a graph that reaches the same
        # collection by many paths linear rather than exponential. Ids are safe as
        # keys: every collection walked is owned by a live app, router or route
        # held on the call stack, so none can be freed and recycled mid-walk.
        key = (id(node), scope.get("path"), scope.get("root_path"))
        if key in seen:
            return False
        seen.add(key)
        return True

    def _unwrap_candidate(self, route: Any) -> Any:
        # FastAPI's include machinery matches through _EffectiveRouteContext proxies
        # that hold the prefix-corrected route; that inner route is what carries the
        # endpoint and the sub-routes, and its child scope is already applied here.
        return (
            getattr(route, "starlette_route", None)
            or getattr(route, "original_route", None)
            or route
        )

    def _route_match(self, route: Any, scope: Any) -> tuple[Match, Any]:
        matches = getattr(route, "matches", None)
        if matches is None:
            return Match.NONE, {}
        try:
            match, child = matches(scope)
        except Exception:
            return Match.NONE, {}
        return match, child

    def _sub_routes(self, route: Any) -> Any:
        # FastAPI's _IncludedRouter keeps sub-routes un-prefixed and only applies the
        # combined include prefix in effective_candidates(); descending into
        # original_router.routes instead resolves nothing past one nesting level.
        candidates = getattr(route, "effective_candidates", None)
        if callable(candidates):
            return candidates()
        included = getattr(route, "original_router", None)
        mounted = getattr(route, "app", None)
        return (
            getattr(route, "routes", None)
            or getattr(included, "routes", None)
            or getattr(mounted, "routes", None)
            or []
        )

    def _populate_guard_state(
        self, guard_request: StarletteGuardRequest, request: Request
    ) -> None:
        app_obj = request.scope.get("app")
        if app_obj and hasattr(app_obj, "state"):
            app_decorator = getattr(app_obj.state, "guard_decorator", None)
            if app_decorator:
                guard_request.state.guard_decorator = app_decorator

        self._routing_app = request.scope.get("app")
        route, path_params = self._resolve_route_with_params(request.scope)
        if not route:
            guard_request.state.guard_route_unresolved = True
            return

        ep = getattr(route, "endpoint", None)
        if ep is None:
            return

        if hasattr(ep, "_guard_route_id"):
            guard_request.state.guard_route_id = ep._guard_route_id
        if hasattr(ep, "__module__") and hasattr(ep, "__qualname__"):
            guard_request.state.guard_endpoint_id = f"{ep.__module__}.{ep.__qualname__}"
        if getattr(self.security_pipeline, "needs_route_identity", False):
            guard_request.state.guard_route_identity = (ep, _path_params(path_params))

    def _path_scope(self, path: str) -> dict[str, Any]:
        return {
            "type": "http",
            "path": path,
            "root_path": "",
            "method": "GET",
            "headers": [],
            "app": self._routing_app,
        }

    def resolve_route(
        self, path: str
    ) -> tuple[tuple[Any, tuple[tuple[str, str], ...]], ...]:
        identities = {
            (endpoint, _path_params(params)): None
            for route, params in self._matching_routes(
                self._path_scope(path), _FULL_OR_PARTIAL
            )
            if (endpoint := getattr(route, "endpoint", None)) is not None
        }
        return tuple(identities)

    def allowed_methods(self, path: str) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    method
                    for route, _ in self._matching_routes(
                        self._path_scope(path), _FULL_OR_PARTIAL
                    )
                    for method in getattr(route, "methods", None) or ()
                }
            )
        )

    def static_route_prefixes(self) -> tuple[str, ...]:
        routes = getattr(self._routing_app, "routes", None)
        if routes is None:
            return ("/",)
        return tuple(_router_route_prefixes(routes, ""))

    def _build_preflight_starlette_response(
        self, request_headers: Any
    ) -> StarletteResponse:
        assert self._cors_handler is not None
        preflight = self._cors_handler.build_preflight_response(request_headers)
        return StarletteResponse(
            content=preflight.body,
            status_code=preflight.status_code,
            headers=preflight.headers,
        )

    def _inject_cors_headers(self, response: Response, request_headers: Any) -> None:
        if self._cors_handler is None:
            return
        cors_headers = self._cors_handler.build_response_headers(request_headers)
        for key, value in cors_headers.items():
            if key.lower() == "vary":
                value = merge_vary(response.headers.getlist("vary"), value)
            response.headers[key] = value

    async def _handle_preflight(
        self, request: Request, guard_request: StarletteGuardRequest
    ) -> Response | None:
        if self._cors_handler is None:
            return None
        if not is_preflight(request.method, request.headers):
            return None
        assert self.security_pipeline is not None
        blocking = await self.security_pipeline.execute(guard_request)
        if blocking is not None:
            blocked = unwrap_response(blocking)
            self._inject_cors_headers(blocked, request.headers)
            return blocked
        return self._build_preflight_starlette_response(request.headers)

    async def _handle_passthrough(
        self,
        request: Request,
        guard_request: StarletteGuardRequest,
        wrapped_call_next: Callable[[GuardRequest], Awaitable[GuardResponse]],
    ) -> Response | None:
        passthrough = await self.bypass_handler.handle_passthrough(
            guard_request, wrapped_call_next
        )
        if passthrough is None:
            return None
        passthrough_response = unwrap_response(passthrough)
        self._inject_cors_headers(passthrough_response, request.headers)
        return passthrough_response

    async def _handle_security_bypass(
        self,
        request: Request,
        guard_request: StarletteGuardRequest,
        wrapped_call_next: Callable[[GuardRequest], Awaitable[GuardResponse]],
        route_config: RouteConfig | None,
    ) -> Response | None:
        bypass = await self.bypass_handler.handle_security_bypass(
            guard_request, wrapped_call_next, route_config
        )
        if bypass is None:
            return None
        bypass_response = unwrap_response(bypass)
        self._inject_cors_headers(bypass_response, request.headers)
        return bypass_response

    async def _handle_pipeline_block(
        self, request: Request, guard_request: StarletteGuardRequest
    ) -> Response | None:
        assert self.security_pipeline is not None
        blocking = await self.security_pipeline.execute(guard_request)
        if blocking is None:
            return None
        blocked = unwrap_response(blocking)
        self._inject_cors_headers(blocked, request.headers)
        return blocked

    async def _redis_unavailable_response(self) -> Response:
        guard_response = await self.create_error_response(
            503, "Service temporarily unavailable"
        )
        guard_response.headers["Retry-After"] = "5"
        return unwrap_response(guard_response)

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        try:
            await self._ensure_initialized(request)
        except GuardRedisError as e:
            self.logger.error("Redis unavailable during initialization: %s", e)
            response = await self._redis_unavailable_response()
            self._inject_cors_headers(response, request.headers)
            return response

        guard_request = StarletteGuardRequest(request)
        wrapped_call_next = wrap_call_next(call_next, request)
        self._populate_guard_state(guard_request, request)

        preflight_response = await self._handle_preflight(request, guard_request)
        if preflight_response is not None:
            return preflight_response

        passthrough_response = await self._handle_passthrough(
            request, guard_request, wrapped_call_next
        )
        if passthrough_response is not None:
            return passthrough_response

        client_ip = await extract_client_ip(
            guard_request, self.config, self.agent_handler
        )
        route_config = self.route_resolver.get_route_config(guard_request)

        bypass_response = await self._handle_security_bypass(
            request, guard_request, wrapped_call_next, route_config
        )
        if bypass_response is not None:
            return bypass_response

        blocked_response = await self._handle_pipeline_block(request, guard_request)
        if blocked_response is not None:
            return blocked_response

        throttled_response = await self._apply_usage_rules(
            request, guard_request, client_ip, route_config
        )
        if throttled_response is not None:
            return throttled_response

        start_time = time.time()
        response = await call_next(request)
        response_time = time.time() - start_time

        processed = await self._process_response(
            request, response, response_time, route_config
        )
        self._inject_cors_headers(processed, request.headers)
        return processed

    async def _apply_usage_rules(
        self,
        request: Request,
        guard_request: StarletteGuardRequest,
        client_ip: str | None,
        route_config: RouteConfig | None,
    ) -> Response | None:
        has_route_rules = route_config is not None and bool(route_config.behavior_rules)
        if not client_ip or not (has_route_rules or self._global_throttle_rules):
            return None
        refused = await self.behavioral_processor.process_usage_rules(
            guard_request, client_ip, route_config
        )
        if refused is None:
            return None
        response = unwrap_response(refused)
        self._inject_cors_headers(response, request.headers)
        return response

    async def _process_decorator_usage_rules(
        self, request: Request, client_ip: str, route_config: RouteConfig
    ) -> Response | None:
        guard_request = StarletteGuardRequest(request)
        refused = await self.behavioral_processor.process_usage_rules(
            guard_request, client_ip, route_config
        )
        return None if refused is None else unwrap_response(refused)

    async def _process_decorator_return_rules(
        self,
        request: Request,
        response: Response,
        client_ip: str,
        route_config: RouteConfig,
    ) -> None:
        from guard.adapters import StarletteGuardResponse

        guard_request = StarletteGuardRequest(request)
        guard_response = StarletteGuardResponse(response)
        await self.behavioral_processor.process_return_rules(
            guard_request, guard_response, client_ip, route_config
        )

    def _get_endpoint_id(self, request: Request) -> str:
        guard_request = StarletteGuardRequest(request)
        result: str = self.behavioral_processor.get_endpoint_id(guard_request)
        return result

    async def refresh_cloud_ip_ranges(self) -> None:
        if not self.config.block_cloud_providers:
            return

        providers: set[str] = {
            str(provider) for provider in self.config.block_cloud_providers
        }

        if self.config.enable_redis and self.redis_handler:
            await cloud_handler.refresh_async(
                providers,
                ttl=self.config.cloud_ip_refresh_interval,
            )
        else:
            await cloud_handler.refresh(providers)
        self.last_cloud_ip_refresh = int(time.time())

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        return await self.response_factory.create_error_response(
            status_code, default_message
        )

    async def reset(self) -> None:
        await self.rate_limit_handler.reset()

    async def initialize(self) -> None:
        self._build_security_pipeline()

        self.handler_initializer.guard_decorator = self.guard_decorator

        await self.handler_initializer.initialize_redis_handlers()

        await self.handler_initializer.initialize_agent_integrations()

        if self.handler_initializer.composite_handler is not None:
            self.agent_handler = self.handler_initializer.composite_handler
            self.event_bus = self.handler_initializer.build_event_bus(
                geo_ip_handler=self.geo_ip_handler
            )
            self.metrics_collector = self.handler_initializer.build_metrics_collector()
            self._build_event_dependent_contexts()

    def get_initialization_status(self) -> dict[str, Any]:
        status = self.handler_initializer.get_initialization_status()
        return cast(dict[str, Any], jsonable_encoder(status))
