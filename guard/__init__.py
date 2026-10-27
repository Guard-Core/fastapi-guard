from importlib.metadata import PackageNotFoundError, version as _pkg_version
from typing import TYPE_CHECKING

import guard_core
from guard_core import (
    BehaviorRule as BehaviorRule,
    BehaviorTracker as BehaviorTracker,
    BoundedBodyReader as BoundedBodyReader,
    BoundedResponseBodyReader as BoundedResponseBodyReader,
    GeoIPHandler as GeoIPHandler,
    GuardRequest as GuardRequest,
    GuardResponse as GuardResponse,
    GuardResponseFactory as GuardResponseFactory,
    IPBanManager as IPBanManager,
    RedisHandlerProtocol as RedisHandlerProtocol,
    RouteConfig as RouteConfig,
    SecurityConfig as SecurityConfig,
    SecurityDecorator as SecurityDecorator,
    SecurityHeadersManager as SecurityHeadersManager,
    check_ip_access as check_ip_access,
    ip_ban_manager as ip_ban_manager,
    is_ip_allowed as is_ip_allowed,
    security_headers_manager as security_headers_manager,
    sus_patterns_handler as sus_patterns_handler,
)
from guard_core._config_capabilities import register_adapter

from guard.asgi import PureASGISecurityMiddleware as PureASGISecurityMiddleware
from guard.middleware import SecurityMiddleware as SecurityMiddleware
from guard.websocket import (
    WS_CLOSE_CLIENT_ADDRESS_UNKNOWN as WS_CLOSE_CLIENT_ADDRESS_UNKNOWN,
    WS_CLOSE_EMERGENCY_MODE as WS_CLOSE_EMERGENCY_MODE,
    WS_CLOSE_IP_BANNED as WS_CLOSE_IP_BANNED,
    WS_CLOSE_IP_NOT_ALLOWED as WS_CLOSE_IP_NOT_ALLOWED,
    WS_CLOSE_RATE_LIMIT_EXCEEDED as WS_CLOSE_RATE_LIMIT_EXCEEDED,
    WS_CLOSE_REASONS as WS_CLOSE_REASONS,
    WS_CLOSE_SECURITY_CHECK_FAILED as WS_CLOSE_SECURITY_CHECK_FAILED,
    WS_CLOSE_SUSPICIOUS_ACTIVITY as WS_CLOSE_SUSPICIOUS_ACTIVITY,
    WS_CLOSE_USER_AGENT_NOT_ALLOWED as WS_CLOSE_USER_AGENT_NOT_ALLOWED,
    WebSocketCloseReason as WebSocketCloseReason,
    guard_websocket as guard_websocket,
    make_guard_websocket as make_guard_websocket,
)

register_adapter("fastapi-guard")

if TYPE_CHECKING:
    from guard_core import (
        CloudManager as CloudManager,
        IPInfoManager as IPInfoManager,
        RateLimitManager as RateLimitManager,
        RedisHandlerBase as RedisHandlerBase,
        RedisManager as RedisManager,
        check_rate_limit_by_ip as check_rate_limit_by_ip,
        cloud_handler as cloud_handler,
        rate_limit_handler as rate_limit_handler,
        redis_handler as redis_handler,
    )

_LAZY_GUARD_CORE_NAMES = frozenset(
    {
        "CloudManager",
        "IPInfoManager",
        "RateLimitManager",
        "RedisHandlerBase",
        "RedisManager",
        "check_rate_limit_by_ip",
        "cloud_handler",
        "rate_limit_handler",
        "redis_handler",
    }
)


def __getattr__(name: str) -> object:
    if name not in _LAZY_GUARD_CORE_NAMES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(guard_core, name)
    globals()[name] = value
    return value


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
    "WS_CLOSE_EMERGENCY_MODE",
    "WS_CLOSE_USER_AGENT_NOT_ALLOWED",
    *guard_core.__all__,
]
