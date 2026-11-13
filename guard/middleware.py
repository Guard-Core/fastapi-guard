import asyncio
import stat
import threading
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Iterable, Iterator, Mapping
from typing import TYPE_CHECKING

from fastapi import Request, Response
from fastapi.encoders import jsonable_encoder
from guard_core import apply_security_headers_settings
from guard_core._utils.app_scope import hold_app_scope, release_app_scope
from guard_core._utils.sampling import observe_sampled_key
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
from guard_core.handlers.cloud_handler import cloud_handler_for
from guard_core.handlers.cors_handler import CorsHandler, is_preflight
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig
from guard_core.protocols import AgentHandlerProtocol, GuardResponse
from guard_core.protocols.agent_protocol import JsonValue
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.utils import (
    extract_client_ip,
    invoke_error_hook,
    setup_custom_logging,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse
from starlette.routing import Host, Match, Mount, get_route_path
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send

from guard._declared_path_params import (
    check_declared_path_params_on_request,
    report_declared_path_params,
)
from guard._lifespan_warm import warm_before_startup_complete
from guard._owned_mounts import owns_its_routes
from guard._response_headers import merge_vary
from guard._route_gate_host import (
    hold_route_gate_host,
    release_route_gate_host,
    route_gate_host,
)
from guard.adapters import (
    StarletteGuardRequest,
    StarletteResponseFactory,
    unwrap_response,
    wrap_call_next,
)

if TYPE_CHECKING:
    from guard._middleware_state import MiddlewareState


def _static_file_is_served(static_files: StaticFiles, scope: Scope) -> bool:
    try:
        _, file_stat = static_files.lookup_path(static_files.get_path(scope))
    except ValueError:
        return False
    return file_stat is not None and stat.S_ISREG(file_stat.st_mode)


_INIT_OUTAGE_SAMPLE_WINDOW_SECONDS = 60
_INIT_OUTAGE_SAMPLE_KEY = "redis_unavailable_during_initialization"
_init_outage_lock = threading.Lock()
_init_outage_samples: OrderedDict[str, float] = OrderedDict()


def _sample_init_outage_line() -> bool:
    return observe_sampled_key(
        _init_outage_samples,
        _init_outage_lock,
        _INIT_OUTAGE_SAMPLE_KEY,
        window=_INIT_OUTAGE_SAMPLE_WINDOW_SECONDS,
        max_tracked=1,
    )


_FULL = (Match.FULL,)
_MOUNT_TEMPLATE = "guard_mount_template"
_ROUTE_TEMPLATE = "guard_route_template"
_OWNED_ROUTES = "guard_owned_routes"
_FULL_OR_PARTIAL = (Match.FULL, Match.PARTIAL)


def _path_params(values: Mapping[str, object]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((name, str(value)) for name, value in values.items()))


def _router_route_prefixes(routes: Iterable[object], base: str) -> list[str]:
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


_PIPELINE_NOT_INITIALIZED = (
    "The security pipeline is not built: the middleware handled a request "
    "before initialization completed"
)


def _route_id_of(endpoint: object, owned: bool) -> str | None:
    # An app mounted with a guard middleware of its own enforces its routes itself.
    return None if owned else getattr(endpoint, "_guard_route_id", None)


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
                from guard_agent import GuardAgentHandler

                if agent_config is None:
                    raise ValueError(
                        "Agent enabled but configuration is invalid. "
                        "Check agent_api_key and other required fields."
                    )
                self.agent_handler = GuardAgentHandler(agent_config)
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
        self._routing_app: object = None

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
            adapter="fastapi-guard",
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

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            send = warm_before_startup_complete(
                send, lambda: self._warm_on_lifespan_startup(scope.get("app"))
            )
        await super().__call__(scope, receive, send)

    async def _warm_on_lifespan_startup(self, app: object) -> None:
        from guard.lifespan import _warm_middleware_or_adopt

        await _warm_middleware_or_adopt(self, app)

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
        check_declared_path_params_on_request(
            self.config,
            request.scope.get("app") if request else self._routing_app,
            self.guard_decorator,
        )
        if not self._is_initialized():
            await self._initialize_once(request)
        await self.handler_initializer.complete_decorator_adoption()

    async def _initialize_once(self, request: Request | None) -> None:
        async with self._init_lock:
            if self._is_initialized():
                return

            from guard._decorator_adoption import adopt_app_state_decorator
            from guard._middleware_state import get_state, state_owner

            decorator = adopt_app_state_decorator(self.guard_decorator, request)
            owner = state_owner(request, self)
            warm = get_state(self.config, decorator, owner)
            if warm is not None:
                self.guard_decorator = decorator
                self.route_resolver.context.guard_decorator = decorator
                self._adopt_warm_state(warm)
                self._initialized = True
                return

            if decorator is not self.guard_decorator:
                self._adopt_decorator(decorator)
            self._warn_if_eager_init_not_honored()
            report_declared_path_params(
                self.config,
                request.scope.get("app") if request else self._routing_app,
                self.guard_decorator,
            )
            await self.initialize()
            self._register_state(owner)
            self._initialized = True

    def _register_state(self, owner: object) -> None:
        from guard._middleware_state import MiddlewareState, register_state

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
            owner,
        )

    def _adopt_warm_state(self, state: "MiddlewareState") -> None:
        self.security_pipeline = state.security_pipeline
        self.event_bus = state.event_bus
        self.metrics_collector = state.metrics_collector
        self.response_factory = state.response_factory
        self.validator = state.validator
        self.bypass_handler = state.bypass_handler
        self.behavioral_processor = state.behavioral_processor
        self.handler_initializer = state.handler_initializer
        if state.composite_handler is not None:
            self.agent_handler = state.composite_handler
        elif state.agent_handler is not None:
            self.agent_handler = state.agent_handler

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
    def agent_stats(self) -> dict[str, JsonValue]:
        if self.agent_handler is None:
            return {"enabled": False, "degraded": self.agent_degraded}
        handler_stats = self.agent_handler.get_stats()
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
        apply_security_headers_settings(security_headers_manager, config)

    def set_decorator_handler(
        self, decorator_handler: BaseSecurityDecorator | None
    ) -> None:
        self._adopt_decorator(decorator_handler)

    def _adopt_decorator(self, decorator: BaseSecurityDecorator | None) -> None:
        # The engine goes first: it can raise, and then nothing here changes. The
        # contexts bind after it returns, so a request on another thread never sees
        # the decorator before its ban manager is injected.
        previous = self.guard_decorator
        self.handler_initializer.adopt_decorator(decorator)
        self.geo_ip_handler = self.handler_initializer.geo_ip_handler
        self.guard_decorator = decorator
        self.route_resolver.context.guard_decorator = decorator
        self.response_factory.context.guard_decorator = decorator
        behavioral = self.behavioral_processor.context
        behavioral.guard_decorator = decorator
        behavioral.behavior_tracker = self.handler_initializer.behavior_tracker
        if self._is_initialized():
            from guard._middleware_state import unregister_state

            owner = self._routing_app if self._routing_app is not None else self
            unregister_state(self.config, previous, owner)
            self._register_state(owner)

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

    def _resolve_route(self, request: Request) -> object:
        return self._resolve_route_with_params(request.scope)[0]

    def _resolve_route_with_params(
        self, scope: Scope
    ) -> tuple[object, dict[str, object]]:
        route, params, _, _ = self._resolve_route_match(scope)
        return route, params

    def _resolve_route_match(
        self, scope: Scope
    ) -> tuple[object, dict[str, object], str | None, bool]:
        route = scope.get("route")
        if route:
            return (
                route,
                scope.get("path_params", {}),
                getattr(route, "path", None),
                False,
            )
        route, params, matched = next(
            self._matching_routes_in_scope(scope, _FULL), (None, {}, {})
        )
        return (
            route,
            params,
            matched.get(_ROUTE_TEMPLATE),
            matched.get(_OWNED_ROUTES, False),
        )

    def _matching_routes(
        self, scope: Scope, accepted: tuple[Match, ...]
    ) -> Iterator[tuple[object, dict[str, object]]]:
        for route, params, _ in self._matching_routes_in_scope(scope, accepted):
            yield route, params

    def _matching_routes_in_scope(
        self, scope: Scope, accepted: tuple[Match, ...]
    ) -> Iterator[tuple[object, dict[str, object], Scope]]:
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
        routes: Iterable[object],
        scope: Scope,
        seen: set[tuple[int, object, object]],
        redirect_slashes: bool,
        accepted: tuple[Match, ...],
    ) -> Iterator[tuple[object, dict[str, object], Scope]]:
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
        self,
        routes: Iterable[object],
        scope: Scope,
        seen: set[tuple[int, object, object]],
        accepted: tuple[Match, ...],
    ) -> Iterator[tuple[object, dict[str, object], Scope]]:
        # This middleware is a BaseHTTPMiddleware, so it runs before the router
        # and scope["route"] is unset. Replicate Starlette's matching, descending
        # into sub-routers / mounts (FastAPI's include_router inserts a wrapper
        # route whose real routes are nested inside), so per-route decorator
        # config resolves for path-parameter and include_router routes, not only
        # routes flattened directly onto the app. Each hit is the route, the path
        # parameters Starlette captured on the way down and the scope the route
        # was matched with (its root_path tells a static mount where it starts).
        if not self._first_visit(seen, routes, scope):
            return
        for r in routes:
            match, child = self._route_match(r, scope)
            if match not in accepted:
                continue
            candidate = r
            r = self._unwrap_candidate(r)
            params = child.get("path_params", {})
            child_scope = {**scope, **child}
            # The template is declared text only: each Mount's own path template and
            # the route's, never root_path, which carries the end user's value. A
            # FastAPI include proxy holds the path with the include prefix applied,
            # which the unwrapped route lacks.
            mount_template = scope.get(_MOUNT_TEMPLATE, "")
            own = getattr(candidate, "path", None)
            if not isinstance(own, str):
                own = getattr(r, "path", None)
            if isinstance(own, str):
                child_scope[_ROUTE_TEMPLATE] = mount_template + own
            if getattr(r, "endpoint", None) is not None:
                yield r, params, child_scope
                continue
            if not self._first_visit(seen, r, child_scope):
                continue
            sub_routes = self._sub_routes(r)
            if not sub_routes:
                yield r, params, child_scope
            else:
                self._enter_mount(r, child_scope, mount_template)
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

    def _enter_mount(
        self, route: object, child_scope: Scope, mount_template: str
    ) -> None:
        if isinstance(route, Mount):
            child_scope[_MOUNT_TEMPLATE] = mount_template + route.path
        if isinstance(route, (Mount, Host)) and owns_its_routes(route):
            child_scope[_OWNED_ROUTES] = True

    def _first_visit(
        self, seen: set[tuple[int, object, object]], node: object, scope: Scope
    ) -> bool:
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

    def _unwrap_candidate(self, route: object) -> object:
        # FastAPI's include machinery matches through _EffectiveRouteContext proxies
        # that hold the prefix-corrected route; that inner route is what carries the
        # endpoint and the sub-routes, and its child scope is already applied here.
        return (
            getattr(route, "starlette_route", None)
            or getattr(route, "original_route", None)
            or route
        )

    def _route_match(self, route: object, scope: Scope) -> tuple[Match, Scope]:
        matches = getattr(route, "matches", None)
        if matches is None:
            return Match.NONE, {}
        try:
            match, child = matches(scope)
        except Exception:
            return Match.NONE, {}
        return match, child

    def _sub_routes(self, route: object) -> Iterable[object]:
        # FastAPI's _IncludedRouter keeps sub-routes un-prefixed and only applies the
        # combined include prefix in effective_candidates(); descending into
        # original_router.routes instead resolves nothing past one nesting level.
        candidates = getattr(route, "effective_candidates", None)
        if callable(candidates):
            effective: Iterable[object] = candidates()
            return effective
        included = getattr(route, "original_router", None)
        mounted = getattr(route, "app", None)
        return (
            getattr(route, "routes", None)
            or getattr(included, "routes", None)
            or getattr(mounted, "routes", None)
            or []
        )

    def _record_route_template(
        self, guard_request: StarletteGuardRequest, template: object
    ) -> None:
        if isinstance(template, str):
            guard_request.state.guard_route_template = template

    def _populate_guard_state(
        self, guard_request: StarletteGuardRequest, request: Request
    ) -> None:
        app_obj = request.scope.get("app")
        if app_obj and hasattr(app_obj, "state"):
            app_decorator = getattr(app_obj.state, "guard_decorator", None)
            if app_decorator:
                guard_request.state.guard_decorator = app_decorator

        self._routing_app = request.scope.get("app")
        route, path_params, template, owned = self._resolve_route_match(request.scope)
        if not route:
            guard_request.state.guard_route_unresolved = True
            return

        self._record_route_template(guard_request, template)

        ep = getattr(route, "endpoint", None)
        if ep is None:
            return

        route_id = _route_id_of(ep, owned)
        if route_id is not None:
            guard_request.state.guard_route_id = route_id
        if hasattr(ep, "__module__") and hasattr(ep, "__qualname__"):
            guard_request.state.guard_endpoint_id = f"{ep.__module__}.{ep.__qualname__}"
        if getattr(self.security_pipeline, "needs_route_identity", False):
            guard_request.state.guard_route_identity = (ep, _path_params(path_params))

    def _path_scope(self, path: str) -> Scope:
        return {
            "type": "http",
            "path": path,
            "root_path": "",
            "method": "GET",
            "headers": [(b"host", route_gate_host().encode("latin-1"))],
            "app": self._routing_app,
        }

    async def static_file_exists(self, path: str) -> bool:
        scope = self._path_scope(path)
        route, _, matched_scope = next(
            self._matching_routes_in_scope(scope, _FULL), (None, {}, {})
        )
        static_files = getattr(route, "_base_app", getattr(route, "app", None))
        if not isinstance(route, Mount) or not isinstance(static_files, StaticFiles):
            return False
        return await asyncio.to_thread(
            _static_file_is_served, static_files, matched_scope
        )

    def resolve_route(
        self, path: str
    ) -> tuple[tuple[object, tuple[tuple[str, str], ...]], ...]:
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
        self, cors_handler: CorsHandler, request_headers: Mapping[str, str]
    ) -> StarletteResponse:
        preflight = cors_handler.build_preflight_response(request_headers)
        return StarletteResponse(
            content=preflight.body,
            status_code=preflight.status_code,
            headers=preflight.headers,
        )

    def _inject_cors_headers(
        self, response: Response, request_headers: Mapping[str, str]
    ) -> None:
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
        cors_handler = self._cors_handler
        if cors_handler is None:
            return None
        if not is_preflight(request.method, request.headers):
            return None
        pipeline = self.security_pipeline
        if pipeline is None:
            raise RuntimeError(_PIPELINE_NOT_INITIALIZED)
        blocking = await pipeline.execute(guard_request)
        if blocking is not None:
            blocked = unwrap_response(blocking)
            self._inject_cors_headers(blocked, request.headers)
            return blocked
        return self._build_preflight_starlette_response(cors_handler, request.headers)

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
        pipeline = self.security_pipeline
        if pipeline is None:
            raise RuntimeError(_PIPELINE_NOT_INITIALIZED)
        blocking = await pipeline.execute(guard_request)
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
            if self.config.passive_mode:
                if _sample_init_outage_line():
                    self.logger.error(
                        "Redis unavailable during initialization: %s "
                        "(passive_mode=True, request passed through unguarded)",
                        e,
                    )
                return await call_next(request)
            self.logger.error("Redis unavailable during initialization: %s", e)
            response = await self._redis_unavailable_response()
            self._inject_cors_headers(response, request.headers)
            return response

        token = hold_app_scope(self.config)
        host_token = hold_route_gate_host(request.headers.get("host", ""))
        try:
            return await self._dispatch_after_init(request, call_next)
        finally:
            release_route_gate_host(host_token)
            release_app_scope(token)

    async def _dispatch_after_init(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
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

        cloud_manager = cloud_handler_for(self.config)
        if self.config.enable_redis and self.redis_handler:
            await cloud_manager.refresh_async(
                providers,
                ttl=self.config.cloud_ip_refresh_interval,
            )
        else:
            await cloud_manager.refresh(providers)
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
        if self.security_pipeline is None:
            self._build_security_pipeline()

        await self.handler_initializer.initialize_redis_handlers()
        self.geo_ip_handler = self.handler_initializer.geo_ip_handler

        await self.handler_initializer.initialize_agent_integrations()

        if self.handler_initializer.composite_handler is not None:
            self.agent_handler = self.handler_initializer.composite_handler
            self.event_bus = self.handler_initializer.build_event_bus(
                geo_ip_handler=self.geo_ip_handler
            )
            self.metrics_collector = self.handler_initializer.build_metrics_collector()
            self._build_event_dependent_contexts()

    def get_initialization_status(self) -> dict[str, JsonValue]:
        status = self.handler_initializer.get_initialization_status()
        encoded: dict[str, JsonValue] = jsonable_encoder(status)
        return encoded
