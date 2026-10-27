import os

from fastapi import status
from fastapi.responses import JSONResponse

from guard import GuardRequest, GuardResponse, SecurityConfig, SecurityDecorator
from guard.adapters import StarletteGuardResponse


async def custom_request_check(request: GuardRequest) -> GuardResponse | None:
    if "debug" in request.query_params and request.query_params["debug"] == "true":
        return StarletteGuardResponse(
            JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Debug mode not allowed"},
            )
        )
    return None


async def custom_response_modifier(response: GuardResponse) -> GuardResponse:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def demo_auth_verifier(request: GuardRequest, credential: str) -> dict[str, str]:
    return {"user": "demo", "credential": credential}


security_config = SecurityConfig(
    whitelist=(),
    blacklist=("192.168.100.0/24",),
    trusted_proxies=("172.16.0.0/12", "10.0.0.0/8"),
    trusted_proxy_depth=1,
    trust_x_forwarded_proto=True,
    ipinfo_token=os.environ.get("IPINFO_TOKEN"),
    block_cloud_providers=frozenset({"AWS", "GCP", "Azure"}),
    blocked_user_agents=["badbot", "evil-crawler", "sqlmap"],
    enable_rate_limiting=True,
    rate_limit=30,
    rate_limit_window=60,
    enable_ip_banning=True,
    auto_ban_threshold=5,
    auto_ban_duration=300,
    enable_penetration_detection=True,
    cloud_ip_refresh_interval=1800,
    log_format="json",
    enable_redis=True,
    redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379"),
    redis_prefix=os.environ.get("REDIS_PREFIX", "fastapi_guard:"),
    enforce_https=False,
    custom_request_check=custom_request_check,
    custom_response_modifier=custom_response_modifier,
    auth_verifier=demo_auth_verifier,
    security_headers={
        "enabled": True,
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'strict-dynamic'"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:", "https:"],
            "font-src": ["'self'", "https://fonts.gstatic.com"],
            "connect-src": ["'self'", "wss://localhost:8000"],
        },
        "hsts": {
            "max_age": 31536000,
            "include_subdomains": True,
            "preload": False,
        },
        "frame_options": "SAMEORIGIN",
        "referrer_policy": "strict-origin-when-cross-origin",
        "permissions_policy": (
            "accelerometer=(), camera=(), geolocation=(), "
            "gyroscope=(), magnetometer=(), microphone=(), "
            "payment=(), usb=()"
        ),
        "custom": {
            "X-App-Name": "FastAPI-Guard-Advanced-Example",
            "X-Security-Contact": "security@example.com",
        },
    },
    enable_cors=True,
    cors_allow_origins=["http://localhost:3000", "https://example.com"],
    cors_allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    cors_allow_headers=["*"],
    cors_allow_credentials=True,
    cors_expose_headers=["X-Total-Count"],
    cors_max_age=3600,
    log_request_level="INFO",
    log_suspicious_level="WARNING",
    custom_log_file="security.log",
    exclude_paths=[
        "/docs",
        "/redoc",
        "/openapi.json",
        "/favicon.ico",
        "/static",
        "/health",
        "/ready",
    ],
    passive_mode=False,
)

guard = SecurityDecorator(security_config)


def build_pure_asgi_config() -> SecurityConfig:
    """The config of the pure-ASGI sub-app mounted at /pure.

    It differs from the main config by one blocked user agent and its own Redis
    prefix, so a request that only the pure-ASGI middleware refuses is visible.
    """
    values = security_config.model_dump()
    values["blocked_user_agents"] = [*values["blocked_user_agents"], "pure-only-bot"]
    values["redis_prefix"] = f"{security_config.redis_prefix}pure:"
    return SecurityConfig(**values)
