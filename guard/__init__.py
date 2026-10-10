from importlib.metadata import PackageNotFoundError, version as _pkg_version

import guard_core
from guard_core import (
    BehaviorRule as BehaviorRule,
    BehaviorTracker as BehaviorTracker,
    BoundedBodyReader as BoundedBodyReader,
    BoundedResponseBodyReader as BoundedResponseBodyReader,
    CloudManager as CloudManager,
    GeoIPHandler as GeoIPHandler,
    GuardRequest as GuardRequest,
    GuardResponse as GuardResponse,
    GuardResponseFactory as GuardResponseFactory,
    IPBanManager as IPBanManager,
    IPInfoManager as IPInfoManager,
    RateLimitManager as RateLimitManager,
    RedisHandlerProtocol as RedisHandlerProtocol,
    RedisManager as RedisManager,
    RouteConfig as RouteConfig,
    SecurityConfig as SecurityConfig,
    SecurityDecorator as SecurityDecorator,
    SecurityHeadersManager as SecurityHeadersManager,
    check_ip_access as check_ip_access,
    check_rate_limit_by_ip as check_rate_limit_by_ip,
    cloud_handler as cloud_handler,
    ip_ban_manager as ip_ban_manager,
    is_ip_allowed as is_ip_allowed,
    rate_limit_handler as rate_limit_handler,
    redis_handler as redis_handler,
    security_headers_manager as security_headers_manager,
    sus_patterns_handler as sus_patterns_handler,
)

from guard.asgi import PureASGISecurityMiddleware as PureASGISecurityMiddleware
from guard.middleware import SecurityMiddleware as SecurityMiddleware
from guard.websocket import (
    WS_CLOSE_CLIENT_ADDRESS_UNKNOWN as WS_CLOSE_CLIENT_ADDRESS_UNKNOWN,
    WS_CLOSE_IP_BANNED as WS_CLOSE_IP_BANNED,
    WS_CLOSE_IP_NOT_ALLOWED as WS_CLOSE_IP_NOT_ALLOWED,
    WS_CLOSE_RATE_LIMIT_EXCEEDED as WS_CLOSE_RATE_LIMIT_EXCEEDED,
    WS_CLOSE_REASONS as WS_CLOSE_REASONS,
    WS_CLOSE_SECURITY_CHECK_FAILED as WS_CLOSE_SECURITY_CHECK_FAILED,
    WS_CLOSE_SUSPICIOUS_ACTIVITY as WS_CLOSE_SUSPICIOUS_ACTIVITY,
    WebSocketCloseReason as WebSocketCloseReason,
    guard_websocket as guard_websocket,
    make_guard_websocket as make_guard_websocket,
)

try:
    __version__ = _pkg_version("fastapi-guard")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = [
    "__version__",
    "PureASGISecurityMiddleware",
    "SecurityMiddleware",
    "guard_websocket",
    "make_guard_websocket",
    "WebSocketCloseReason",
    "WS_CLOSE_REASONS",
    "WS_CLOSE_IP_BANNED",
    "WS_CLOSE_IP_NOT_ALLOWED",
    "WS_CLOSE_RATE_LIMIT_EXCEEDED",
    "WS_CLOSE_CLIENT_ADDRESS_UNKNOWN",
    "WS_CLOSE_SECURITY_CHECK_FAILED",
    "WS_CLOSE_SUSPICIOUS_ACTIVITY",
    *guard_core.__all__,
]
