import ipaddress
import logging
import weakref
from collections.abc import Awaitable, Callable, Mapping
from typing import NamedTuple

from guard_core import check_rate_limit_by_ip, is_ip_allowed
from guard_core.adapter_support import register_per_app_record
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.implementations.authentication import AuthenticationCheck
from guard_core.core.checks.implementations.cloud_ip_refresh import CloudIpRefreshCheck
from guard_core.core.checks.implementations.cloud_provider import CloudProviderCheck
from guard_core.core.checks.implementations.custom_request import CustomRequestCheck
from guard_core.core.checks.implementations.custom_validators import (
    CustomValidatorsCheck,
)
from guard_core.core.checks.implementations.emergency_mode import EmergencyModeCheck
from guard_core.core.checks.implementations.https_enforcement import (
    HttpsEnforcementCheck,
)
from guard_core.core.checks.implementations.referrer import ReferrerCheck
from guard_core.core.checks.implementations.request_logging import RequestLoggingCheck
from guard_core.core.checks.implementations.required_headers import (
    RequiredHeadersCheck,
)
from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.core.checks.implementations.time_window import TimeWindowCheck
from guard_core.core.checks.implementations.user_agent import UserAgentCheck
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.core.events import SecurityEventBus
from guard_core.core.routing import RouteConfigResolver, RoutingContext
from guard_core.core.validation import RequestValidator, ValidationContext
from guard_core.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.exceptions import GuardRedisError
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from guard_core.protocols import AgentHandlerProtocol, GuardResponseFactory
from guard_core.protocols.geo_ip_protocol import GeoIPHandler
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import UNKNOWN_CLIENT_IDENTITY, extract_client_ip, log_activity
from starlette import status
from starlette.datastructures import State
from starlette.exceptions import WebSocketException
from starlette.routing import get_route_path
from starlette.websockets import WebSocket

from guard._decorator_adoption import resolve_app_state_decorator
from guard._middleware_state import get_state
from guard.adapters import _join_repeated_header_lines, asgi_scope_as_dict
from guard.lifespan import (
    _find_security_config,
    _find_security_middleware,
    _find_security_redis_handler,
    initialize_like_http_if_cold,
)
from guard.middleware import SecurityMiddleware

logger = logging.getLogger("guard_core")


class WebSocketCloseReason(NamedTuple):
    code: int
    reason: str


WS_CLOSE_IP_BANNED = WebSocketCloseReason(status.WS_1008_POLICY_VIOLATION, "IP banned")
WS_CLOSE_IP_NOT_ALLOWED = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "IP not allowed"
)
WS_CLOSE_RATE_LIMIT_EXCEEDED = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "Rate limit exceeded"
)
WS_CLOSE_CLIENT_ADDRESS_UNKNOWN = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "Client address could not be determined"
)
WS_CLOSE_SECURITY_CHECK_FAILED = WebSocketCloseReason(
    status.WS_1013_TRY_AGAIN_LATER, "Security check failed"
)
WS_CLOSE_SUSPICIOUS_ACTIVITY = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "Suspicious activity detected"
)

WS_CLOSE_EMERGENCY_MODE = WebSocketCloseReason(
    status.WS_1013_TRY_AGAIN_LATER, "Service temporarily unavailable"
)
WS_CLOSE_USER_AGENT_NOT_ALLOWED = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "User agent not allowed"
)

WS_CLOSE_HTTPS_REQUIRED = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "HTTPS required"
)
WS_CLOSE_CLOUD_PROVIDER_BLOCKED = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "Cloud provider IP not allowed"
)
WS_CLOSE_REQUIRED_HEADER_MISSING = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "Required header missing"
)
WS_CLOSE_AUTHENTICATION_REQUIRED = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "Authentication required"
)
WS_CLOSE_REFERRER_REQUIRED = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "Referrer not allowed"
)
WS_CLOSE_VALIDATION_FAILED = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "Request validation failed"
)
WS_CLOSE_OUTSIDE_TIME_WINDOW = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "Access outside the allowed time window"
)
WS_CLOSE_CUSTOM_REQUEST_REFUSED = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "Request refused"
)

_DETECTION_CHECK_FAILED_STATUS_CODE = 500
# guard-core 5.0.0 answers a Redis outage under fail_secure with 503 (D-188)
_REDIS_OUTAGE_STATUS_CODE = 503
_CHECK_FAILED_STATUS_CODES = (
    _DETECTION_CHECK_FAILED_STATUS_CODE,
    _REDIS_OUTAGE_STATUS_CODE,
)

WS_CLOSE_REASONS: tuple[WebSocketCloseReason, ...] = (
    WS_CLOSE_IP_BANNED,
    WS_CLOSE_IP_NOT_ALLOWED,
    WS_CLOSE_RATE_LIMIT_EXCEEDED,
    WS_CLOSE_CLIENT_ADDRESS_UNKNOWN,
    WS_CLOSE_SECURITY_CHECK_FAILED,
    WS_CLOSE_SUSPICIOUS_ACTIVITY,
    WS_CLOSE_EMERGENCY_MODE,
    WS_CLOSE_USER_AGENT_NOT_ALLOWED,
    WS_CLOSE_HTTPS_REQUIRED,
    WS_CLOSE_CLOUD_PROVIDER_BLOCKED,
    WS_CLOSE_REQUIRED_HEADER_MISSING,
    WS_CLOSE_AUTHENTICATION_REQUIRED,
    WS_CLOSE_REFERRER_REQUIRED,
    WS_CLOSE_VALIDATION_FAILED,
    WS_CLOSE_OUTSIDE_TIME_WINDOW,
    WS_CLOSE_CUSTOM_REQUEST_REFUSED,
)


class _WebSocketGuardRequest:
    def __init__(self, websocket: WebSocket) -> None:
        self._websocket = websocket

    @property
    def url_path(self) -> str:
        return get_route_path(self._websocket.scope)

    @property
    def url_scheme(self) -> str:
        # The engine's HTTPS rules know http and https: wss is the TLS handshake.
        scheme = self._websocket.url.scheme
        return {"wss": "https", "ws": "http"}.get(scheme, scheme)

    @property
    def url_full(self) -> str:
        return str(self._websocket.url)

    def url_replace_scheme(self, scheme: str) -> str:
        return str(self._websocket.url.replace(scheme=scheme))

    @property
    def method(self) -> str:
        return "WEBSOCKET"

    @property
    def client_host(self) -> str | None:
        if self._websocket.client:
            return self._websocket.client.host
        return None

    @property
    def headers(self) -> Mapping[str, str]:
        return _join_repeated_header_lines(self._websocket.headers)

    @property
    def query_params(self) -> Mapping[str, str]:
        return self._websocket.query_params

    async def body(self) -> bytes:
        return b""

    @property
    def state(self) -> State:
        return self._websocket.state

    @property
    def scope(self) -> dict[str, object]:
        return asgi_scope_as_dict(self._websocket.scope)


class _WebSocketDetectionResponse:
    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        self.body: bytes | None = message.encode()


class _WebSocketResponseFactory:
    security_headers_manager: object = None

    async def create_https_redirect(self, request: GuardRequest) -> GuardResponse:
        # A handshake cannot be redirected: the refusal closes the socket.
        return _WebSocketDetectionResponse(status.HTTP_403_FORBIDDEN, "HTTPS required")

    async def apply_modifier(
        self, response: GuardResponse, request: GuardRequest | None = None
    ) -> GuardResponse:
        return response


class _WebSocketDetectionMiddleware:
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self.logger = logger
        self.last_cloud_ip_refresh = 0
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self.rate_limit_handler: RateLimitManager | None = None
        self.agent_handler: AgentHandlerProtocol | None = None
        self.guard_response_factory: GuardResponseFactory | None = None
        self.response_factory: _WebSocketResponseFactory | None = (
            _WebSocketResponseFactory()
        )
        self.engine: SecurityMiddleware | None = None
        self.guard_decorator: BaseSecurityDecorator | None = None
        self.geo_ip_handler = config.geo_ip_handler
        self.event_bus = SecurityEventBus(
            self.agent_handler, config, self.geo_ip_handler
        )
        self.route_resolver = RouteConfigResolver(
            RoutingContext(config=config, logger=logger)
        )
        self.validator = RequestValidator(
            ValidationContext(config=config, logger=logger, event_bus=self.event_bus)
        )

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        return _WebSocketDetectionResponse(status_code, default_message)

    async def refresh_cloud_ip_ranges(self) -> None:
        if self.engine is not None:
            await self.engine.refresh_cloud_ip_ranges()


_DETECTION_ATTRIBUTE = "_guard_ws_detection_middleware"
register_per_app_record(_DETECTION_ATTRIBUTE)


class _WeakDetectionMiddlewares(weakref.WeakSet[_WebSocketDetectionMiddleware]):
    """The detection middlewares alive, held weakly: each one is parked on its
    config (like guard-core's app scope), so it lives and dies with that config and
    no store is keyed on an id that could be reused. ``clear`` forgets them all.
    """

    def clear(self) -> None:
        for middleware in list(self):
            middleware.config.__dict__.pop(_DETECTION_ATTRIBUTE, None)
        super().clear()


_ws_detection_middlewares = _WeakDetectionMiddlewares()


def _get_ws_detection_middleware(
    config: SecurityConfig,
) -> _WebSocketDetectionMiddleware:
    middleware: _WebSocketDetectionMiddleware | None = config.__dict__.get(
        _DETECTION_ATTRIBUTE
    )
    if middleware is None or middleware.config is not config:
        middleware = _WebSocketDetectionMiddleware(config)
        object.__setattr__(config, _DETECTION_ATTRIBUTE, middleware)
        _ws_detection_middlewares.add(middleware)
    return middleware


def _resolve_shared_suspicious_counts(
    app: object, config: SecurityConfig
) -> dict[str, dict[str, int]] | None:
    state = get_state(config, resolve_app_state_decorator(app), app)
    if state is None:
        return None
    if state.security_pipeline is None:
        return None
    for check in state.security_pipeline.checks:
        if check.check_name == "suspicious_activity":
            counts: dict[str, dict[str, int]] = (
                check.middleware.suspicious_request_counts
            )
            return counts
    return None


async def _mark_exclusion_scope(
    guard_request: GuardRequest, config: SecurityConfig
) -> None:
    detection_middleware = _get_ws_detection_middleware(config)
    if await detection_middleware.validator.is_path_excluded(guard_request):
        guard_request.state.guard_exclusion_scoped = True


async def _run_penetration_detection(
    guard_request: GuardRequest,
    config: SecurityConfig,
    app: object = None,
) -> None:
    detection_middleware = _get_ws_detection_middleware(config)
    if app is not None:
        shared_counts = _resolve_shared_suspicious_counts(app, config)
        if shared_counts is not None:
            detection_middleware.suspicious_request_counts = shared_counts
    await _mark_exclusion_scope(guard_request, config)
    pipeline = SecurityCheckPipeline(
        [SuspiciousActivityCheck(detection_middleware)],
        config.muted_check_logs,
    )
    response = await pipeline.execute(guard_request)
    if response is not None:
        if response.status_code in _CHECK_FAILED_STATUS_CODES:
            raise WebSocketException(
                code=WS_CLOSE_SECURITY_CHECK_FAILED.code,
                reason=WS_CLOSE_SECURITY_CHECK_FAILED.reason,
            )
        raise WebSocketException(
            code=WS_CLOSE_SUSPICIOUS_ACTIVITY.code,
            reason=WS_CLOSE_SUSPICIOUS_ACTIVITY.reason,
        )


async def _guarded_redis_call(
    awaitable: Awaitable[bool],
    config: SecurityConfig,
    check_name: str,
    default: bool,
) -> bool:
    try:
        return await awaitable
    except GuardRedisError as exc:
        if config.redis_fail_open:
            logger.warning(
                "Skipping %s: Redis unavailable, failing open (redis_fail_open=True)",
                check_name,
            )
            return default
        logger.error("Error in %s: %s", check_name, exc, exc_info=True)
        if config.passive_mode:
            logger.warning(
                "Skipping %s: Redis unavailable, admitting the handshake "
                "(passive_mode=True)",
                check_name,
            )
            return default
        if config.fail_secure:
            logger.warning(
                "Blocking websocket handshake due to %s error in fail-secure mode",
                check_name,
            )
            raise WebSocketException(
                code=WS_CLOSE_SECURITY_CHECK_FAILED.code,
                reason=WS_CLOSE_SECURITY_CHECK_FAILED.reason,
            ) from exc
        return default


def _close_for_check_response(
    response: GuardResponse, denial: WebSocketCloseReason
) -> WebSocketCloseReason:
    if response.status_code == _DETECTION_CHECK_FAILED_STATUS_CODE:
        return WS_CLOSE_SECURITY_CHECK_FAILED
    return denial


async def _run_handshake_check(
    guard_request: GuardRequest,
    config: SecurityConfig,
    check_class: type[SecurityCheck],
    denial: WebSocketCloseReason,
) -> None:
    middleware = _get_ws_detection_middleware(config)
    pipeline = SecurityCheckPipeline(
        [check_class(middleware)],
        config.muted_check_logs,
    )
    response = await pipeline.execute(guard_request)
    if response is not None:
        close = _close_for_check_response(response, denial)
        raise WebSocketException(code=close.code, reason=close.reason)


async def _deny_handshake(
    guard_request: GuardRequest,
    config: SecurityConfig,
    close: WebSocketCloseReason,
    check_name: str,
    reason: str,
) -> None:
    if not config.passive_mode:
        raise WebSocketException(code=close.code, reason=close.reason)
    await log_activity(
        guard_request,
        logger,
        log_type="suspicious",
        reason=reason,
        level=config.log_suspicious_level,
        passive_mode=True,
        check_name=check_name,
        muted_check_logs=config.muted_check_logs,
        on_block=config.on_block,
        sensitive_headers=config.log_sensitive_headers,
        sensitive_params=config.log_sensitive_params,
        sensitive_body_fields=config.log_sensitive_body_fields,
    )


async def _check_ban(
    guard_request: GuardRequest, config: SecurityConfig, client_ip: str
) -> None:
    is_banned = await _guarded_redis_call(
        ip_ban_manager_for(config).is_ip_banned(client_ip),
        config,
        "ip_ban_manager.is_ip_banned",
        default=False,
    )
    if is_banned:
        await _deny_handshake(
            guard_request,
            config,
            WS_CLOSE_IP_BANNED,
            "ip_security",
            f"Banned IP attempted access: {client_ip}",
        )


async def _check_ip_allowed(
    guard_request: GuardRequest, config: SecurityConfig, client_ip: str
) -> bool:
    geo_ip_handler = config.geo_ip_handler
    if not isinstance(geo_ip_handler, GeoIPHandler):
        geo_ip_handler = None
    allowed = await is_ip_allowed(client_ip, config, geo_ip_handler)
    if not allowed:
        await _deny_handshake(
            guard_request,
            config,
            WS_CLOSE_IP_NOT_ALLOWED,
            "ip_security",
            f"IP not allowed: {client_ip}",
        )
    return allowed


async def _check_handshake_rate_limit(
    guard_request: GuardRequest,
    config: SecurityConfig,
    redis_handler: RedisManager | None,
    client_ip: str,
) -> None:
    try:
        ipaddress.ip_address(client_ip)
    except ValueError:
        # An address the rate limiter cannot key: the IP check already refused it
        # (or logged it under passive_mode, which admits the handshake).
        return
    allowed = await _guarded_redis_call(
        check_rate_limit_by_ip(
            client_ip, config, redis_handler=redis_handler, endpoint_path="ws"
        ),
        config,
        "check_rate_limit_by_ip",
        default=True,
    )
    if not allowed:
        await _deny_handshake(
            guard_request,
            config,
            WS_CLOSE_RATE_LIMIT_EXCEEDED,
            "rate_limit",
            f"Rate limit exceeded for IP: {client_ip}",
        )


def _resolve_handshake_route(
    websocket: WebSocket,
    guard_request: GuardRequest,
    config: SecurityConfig,
    app: object,
) -> RouteConfig | None:
    scope_app = app if app is not None else websocket.scope.get("app")
    middleware = _get_ws_detection_middleware(config)
    middleware.engine = (
        None if scope_app is None else _find_security_middleware(scope_app)
    )
    state = websocket.state
    decorator = None if scope_app is None else resolve_app_state_decorator(scope_app)
    if decorator is not None:
        state.guard_decorator = decorator
    route_id = getattr(websocket.scope.get("endpoint"), "_guard_route_id", None)
    if route_id:
        state.guard_route_id = route_id
    route_config = middleware.route_resolver.get_route_config(guard_request)
    state.route_config = route_config
    return route_config


async def _run_applicable_checks(
    guard_request: GuardRequest,
    config: SecurityConfig,
    route_config: RouteConfig | None,
    checks: tuple[tuple[type[SecurityCheck], WebSocketCloseReason], ...],
) -> None:
    route_configs = None if route_config is None else [route_config]
    for check_class, denial in checks:
        if check_class.applies_to(config, route_configs):
            await _mark_exclusion_scope(guard_request, config)
            await _run_handshake_check(guard_request, config, check_class, denial)


_CHECKS_BEFORE_IP_RULES = (
    (HttpsEnforcementCheck, WS_CLOSE_HTTPS_REQUIRED),
    (RequestLoggingCheck, WS_CLOSE_SECURITY_CHECK_FAILED),
)
_CHECKS_AFTER_IP_RULES = (
    (CloudIpRefreshCheck, WS_CLOSE_SECURITY_CHECK_FAILED),
    (CloudProviderCheck, WS_CLOSE_CLOUD_PROVIDER_BLOCKED),
    (UserAgentCheck, WS_CLOSE_USER_AGENT_NOT_ALLOWED),
)
_ROUTE_CHECKS_AFTER_RATE_LIMIT = (
    (RequiredHeadersCheck, WS_CLOSE_REQUIRED_HEADER_MISSING),
    (AuthenticationCheck, WS_CLOSE_AUTHENTICATION_REQUIRED),
    (ReferrerCheck, WS_CLOSE_REFERRER_REQUIRED),
    (CustomValidatorsCheck, WS_CLOSE_VALIDATION_FAILED),
    (TimeWindowCheck, WS_CLOSE_OUTSIDE_TIME_WINDOW),
)


async def _run_websocket_checks(
    websocket: WebSocket,
    config: SecurityConfig,
    redis_handler: RedisManager | None,
    app: object = None,
) -> None:
    guard_request: GuardRequest = _WebSocketGuardRequest(websocket)
    client_ip = await extract_client_ip(guard_request, config)
    websocket.state.client_ip = client_ip
    route_config = _resolve_handshake_route(websocket, guard_request, config, app)

    if client_ip == UNKNOWN_CLIENT_IDENTITY and config.fail_secure:
        await _deny_handshake(
            guard_request,
            config,
            WS_CLOSE_CLIENT_ADDRESS_UNKNOWN,
            "client_address",
            "Client address could not be determined",
        )

    if config.emergency_mode:
        await _run_handshake_check(
            guard_request, config, EmergencyModeCheck, WS_CLOSE_EMERGENCY_MODE
        )

    await _run_applicable_checks(
        guard_request, config, route_config, _CHECKS_BEFORE_IP_RULES
    )
    await _check_ban(guard_request, config, client_ip)
    admitted = await _check_ip_allowed(guard_request, config, client_ip)

    whitelist_skips_checks = bool(config.whitelist) and not getattr(
        config, "whitelist_access_only", False
    )
    # Membership, as the HTTP check decides it: a client that only passed because
    # passive_mode logs the refusal is not on the list.
    is_whitelisted = (
        admitted and client_ip != UNKNOWN_CLIENT_IDENTITY and whitelist_skips_checks
    )
    websocket.state.is_whitelisted = is_whitelisted

    await _run_applicable_checks(
        guard_request, config, route_config, _CHECKS_AFTER_IP_RULES
    )

    if client_ip != UNKNOWN_CLIENT_IDENTITY and not is_whitelisted:
        await _check_handshake_rate_limit(
            guard_request, config, redis_handler, client_ip
        )

    await _run_applicable_checks(
        guard_request, config, route_config, _ROUTE_CHECKS_AFTER_RATE_LIMIT
    )
    await _run_penetration_detection(guard_request, config, app)
    await _run_applicable_checks(
        guard_request,
        config,
        route_config,
        ((CustomRequestCheck, WS_CLOSE_CUSTOM_REQUEST_REFUSED),),
    )


async def _initialize_redis_like_http(
    websocket: WebSocket, config: SecurityConfig, app: object
) -> None:
    try:
        await initialize_like_http_if_cold(app, config)
    except GuardRedisError as exc:
        logger.error("Redis unavailable during initialization: %s", exc)
        await _deny_handshake(
            _WebSocketGuardRequest(websocket),
            config,
            WS_CLOSE_EMERGENCY_MODE,
            "redis_initialization",
            f"Redis unavailable during initialization: {exc}",
        )


async def guard_websocket(websocket: WebSocket) -> None:
    app = websocket.scope.get("app")
    config = _find_security_config(app)
    if config is None:
        raise RuntimeError(
            "guard_websocket requires SecurityMiddleware to be registered via "
            "app.add_middleware(SecurityMiddleware, config=...)"
        )
    redis_handler = _find_security_redis_handler(app)
    if redis_handler is None and config.enable_redis:
        await _initialize_redis_like_http(websocket, config, app)
        redis_handler = _find_security_redis_handler(app)
    await _run_websocket_checks(websocket, config, redis_handler, app)


def make_guard_websocket(
    config: SecurityConfig,
    redis_handler: RedisManager | None = None,
) -> Callable[[WebSocket], Awaitable[None]]:
    if config.enable_redis and redis_handler is None:
        logger.warning(
            "enable_redis=True but no redis_handler was given to "
            "make_guard_websocket; the websocket rate limit uses the "
            "in-memory store"
        )

    async def _guard_websocket_dependency(websocket: WebSocket) -> None:
        await _run_websocket_checks(websocket, config, redis_handler)

    return _guard_websocket_dependency
