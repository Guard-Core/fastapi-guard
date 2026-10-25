import logging
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from typing import Any, NamedTuple, cast

from guard_core import check_rate_limit_by_ip, ip_ban_manager, is_ip_allowed
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.implementations.emergency_mode import EmergencyModeCheck
from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.core.checks.implementations.user_agent import UserAgentCheck
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.core.events import SecurityEventBus
from guard_core.core.routing import RouteConfigResolver, RoutingContext
from guard_core.core.validation import RequestValidator, ValidationContext
from guard_core.decorators.base import BaseSecurityDecorator
from guard_core.exceptions import GuardRedisError
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import UNKNOWN_CLIENT_IDENTITY, extract_client_ip, log_activity
from starlette import status
from starlette.exceptions import WebSocketException
from starlette.routing import get_route_path
from starlette.websockets import WebSocket

from guard._decorator_adoption import resolve_app_state_decorator
from guard._middleware_state import get_state
from guard.adapters import _join_repeated_header_lines
from guard.lifespan import _find_security_config, _find_security_redis_handler

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

_DETECTION_CHECK_FAILED_STATUS_CODE = 500

WS_CLOSE_REASONS: tuple[WebSocketCloseReason, ...] = (
    WS_CLOSE_IP_BANNED,
    WS_CLOSE_IP_NOT_ALLOWED,
    WS_CLOSE_RATE_LIMIT_EXCEEDED,
    WS_CLOSE_CLIENT_ADDRESS_UNKNOWN,
    WS_CLOSE_SECURITY_CHECK_FAILED,
    WS_CLOSE_SUSPICIOUS_ACTIVITY,
    WS_CLOSE_EMERGENCY_MODE,
    WS_CLOSE_USER_AGENT_NOT_ALLOWED,
)


class _WebSocketGuardRequest:
    def __init__(self, websocket: WebSocket) -> None:
        self._websocket = websocket

    @property
    def url_path(self) -> str:
        return get_route_path(self._websocket.scope)

    @property
    def url_scheme(self) -> str:
        return self._websocket.url.scheme

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
    def state(self) -> Any:
        return self._websocket.state

    @property
    def scope(self) -> dict[str, Any]:
        return cast(dict[str, Any], self._websocket.scope)


class _WebSocketDetectionResponse:
    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        self.body: bytes | None = message.encode()


class _WebSocketDetectionMiddleware:
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self.logger = logger
        self.last_cloud_ip_refresh = 0
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self.rate_limit_handler: Any = None
        self.agent_handler: Any = None
        self.guard_response_factory: Any = None
        self.response_factory: Any = None
        self.guard_decorator: BaseSecurityDecorator | None = None
        self.geo_ip_handler = (
            config.geo_ip_handler
            if config.whitelist_countries or config.blocked_countries
            else None
        )
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
        return None


_ws_detection_middlewares: dict[int, _WebSocketDetectionMiddleware] = {}


def _get_ws_detection_middleware(
    config: SecurityConfig,
) -> _WebSocketDetectionMiddleware:
    key = id(config)
    middleware = _ws_detection_middlewares.get(key)
    if middleware is None:
        middleware = _WebSocketDetectionMiddleware(config)
        _ws_detection_middlewares[key] = middleware
    return middleware


def _resolve_shared_suspicious_counts(
    app: Any, config: SecurityConfig
) -> dict[str, dict[str, int]] | None:
    state = get_state(config, resolve_app_state_decorator(app))
    if state is None:
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
    app: Any = None,
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
        if response.status_code == _DETECTION_CHECK_FAILED_STATUS_CODE:
            raise WebSocketException(
                code=WS_CLOSE_SECURITY_CHECK_FAILED.code,
                reason=WS_CLOSE_SECURITY_CHECK_FAILED.reason,
            )
        raise WebSocketException(
            code=WS_CLOSE_SUSPICIOUS_ACTIVITY.code,
            reason=WS_CLOSE_SUSPICIOUS_ACTIVITY.reason,
        )


async def _guarded_redis_call(
    awaitable: Coroutine[Any, Any, bool],
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
        ip_ban_manager.is_ip_banned(client_ip),
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
) -> None:
    if not await is_ip_allowed(client_ip, config, config.geo_ip_handler):
        await _deny_handshake(
            guard_request,
            config,
            WS_CLOSE_IP_NOT_ALLOWED,
            "ip_security",
            f"IP not allowed: {client_ip}",
        )


async def _check_handshake_rate_limit(
    guard_request: GuardRequest,
    config: SecurityConfig,
    redis_handler: RedisManager | None,
    client_ip: str,
) -> None:
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


def _user_agent_check_applies(config: SecurityConfig) -> bool:
    return bool(config.blocked_user_agents) or config.block_empty_user_agent


async def _run_websocket_checks(
    websocket: WebSocket,
    config: SecurityConfig,
    redis_handler: RedisManager | None,
    app: Any = None,
) -> None:
    guard_request: GuardRequest = _WebSocketGuardRequest(websocket)
    client_ip = await extract_client_ip(guard_request, config)
    websocket.state.client_ip = client_ip

    if client_ip == UNKNOWN_CLIENT_IDENTITY and config.fail_secure:
        raise WebSocketException(
            code=WS_CLOSE_CLIENT_ADDRESS_UNKNOWN.code,
            reason=WS_CLOSE_CLIENT_ADDRESS_UNKNOWN.reason,
        )

    if config.emergency_mode:
        await _run_handshake_check(
            guard_request, config, EmergencyModeCheck, WS_CLOSE_EMERGENCY_MODE
        )

    await _check_ban(guard_request, config, client_ip)
    await _check_ip_allowed(guard_request, config, client_ip)

    whitelist_skips_checks = bool(config.whitelist) and not getattr(
        config, "whitelist_access_only", False
    )
    is_whitelisted = client_ip != UNKNOWN_CLIENT_IDENTITY and whitelist_skips_checks
    websocket.state.is_whitelisted = is_whitelisted

    if _user_agent_check_applies(config):
        await _mark_exclusion_scope(guard_request, config)
        await _run_handshake_check(
            guard_request, config, UserAgentCheck, WS_CLOSE_USER_AGENT_NOT_ALLOWED
        )

    if client_ip != UNKNOWN_CLIENT_IDENTITY and not whitelist_skips_checks:
        await _check_handshake_rate_limit(
            guard_request, config, redis_handler, client_ip
        )

    await _run_penetration_detection(guard_request, config, app)


async def guard_websocket(websocket: WebSocket) -> None:
    app = websocket.scope.get("app")
    config = _find_security_config(app)
    if config is None:
        raise RuntimeError(
            "guard_websocket requires SecurityMiddleware to be registered via "
            "app.add_middleware(SecurityMiddleware, config=...)"
        )
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
