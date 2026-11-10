"""
FastAPI Guard Comprehensive Example
===================================

This example demonstrates ALL features of the FastAPI Guard security middleware.

Features demonstrated:
- IP whitelisting/blacklisting with CIDR support
- Country-based filtering (blocking and allowing)
- Cloud provider IP blocking
- Rate limiting (global and per-endpoint)
- Automatic IP banning
- Penetration attempt detection
- User agent filtering
- Content type filtering
- Request size limiting
- Time-based access control
- Behavioral analysis and monitoring
- Custom authentication schemes
- Honeypot detection
- Redis integration for distributed environments
- Agent integration for telemetry
- Dynamic rule management
- Emergency mode
- WebSocket protection
- And much more!

Run with: uvicorn main:app --reload
"""

import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse
from guard_core.handlers.cloud_handler import cloud_handler_for
from pydantic import BaseModel, ConfigDict, Field

from guard import (
    BehaviorRule,
    GuardRequest,
    GuardResponse,
    SecurityConfig,
    SecurityDecorator,
    SecurityMiddleware,
    guard_websocket,
)
from guard.adapters import StarletteGuardResponse
from guard.lifespan import make_lifespan
from guard.status import add_status_route

# Configure logging
# FastAPI Guard uses its own logger hierarchy under "fastapi_guard" namespace
# This basic config is for the example app's own logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Note: FastAPI Guard automatically sets up its own logging via the middleware
# with console output always enabled and optional file logging based on config


# ==================== Response Models ====================


class MessageResponse(BaseModel):
    message: str
    details: dict[str, Any] | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Success",
                "details": {"info": "Additional information"},
            }
        }
    )


class IPInfoResponse(BaseModel):
    ip: str
    country: str | None = None
    city: str | None = None
    region: str | None = None
    is_vpn: bool | None = None
    is_cloud: bool | None = None
    cloud_provider: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "ip": "8.8.8.8",
                "country": "US",
                "city": "Mountain View",
                "region": "California",
                "is_vpn": False,
                "is_cloud": True,
                "cloud_provider": "Google",
            }
        }
    )


class StatsResponse(BaseModel):
    total_requests: int
    blocked_requests: int
    banned_ips: list[str]
    rate_limited_ips: dict[str, int]
    suspicious_activities: list[dict[str, Any]]
    active_rules: dict[str, Any]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "total_requests": 1000,
                "blocked_requests": 50,
                "banned_ips": ["192.168.1.100", "10.0.0.50"],
                "rate_limited_ips": {"192.168.1.200": 5},
                "suspicious_activities": [
                    {"ip": "192.168.1.100", "reason": "SQL injection attempt"}
                ],
                "active_rules": {"rate_limit": 10, "auto_ban_threshold": 5},
            }
        }
    )


class ErrorResponse(BaseModel):
    detail: str
    error_code: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "detail": "Access denied",
                "error_code": "ACCESS_DENIED",
                "timestamp": "2024-01-20T10:30:00Z",
            }
        }
    )


class AuthResponse(BaseModel):
    authenticated: bool
    user: str | None = None
    method: str
    permissions: list[str] = Field(default_factory=list)


class TestPayload(BaseModel):
    input: str | None = Field(None, description="Test input for XSS detection")
    query: str | None = Field(None, description="Test query for SQL injection")
    path: str | None = Field(None, description="Test path for traversal attacks")
    cmd: str | None = Field(None, description="Test command for injection")
    honeypot_field: str | None = Field(
        None, description="Hidden field for bot detection"
    )


class HealthResponse(BaseModel):
    status: str
    timestamp: datetime

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "healthy",
                "timestamp": "2024-01-20T10:30:00Z",
            }
        }
    )


class CspViolationReport(BaseModel):
    blocked_uri: str | None = Field(None, alias="blocked-uri")
    disposition: str | None = None
    document_uri: str | None = Field(None, alias="document-uri")
    effective_directive: str | None = Field(None, alias="effective-directive")
    original_policy: str | None = Field(None, alias="original-policy")
    referrer: str | None = None
    script_sample: str | None = Field(None, alias="script-sample")
    status_code: int | None = Field(None, alias="status-code")
    violated_directive: str | None = Field(None, alias="violated-directive")
    source_file: str | None = Field(None, alias="source-file")
    line_number: int | None = Field(None, alias="line-number")
    column_number: int | None = Field(None, alias="column-number")

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "blocked-uri": "https://evil.com/script.js",
                "document-uri": "https://example.com/page",
                "violated-directive": "script-src 'self'",
                "source-file": "https://example.com/page",
                "line-number": 42,
            }
        },
    )


class CspReportWrapper(BaseModel):
    csp_report: CspViolationReport = Field(alias="csp-report")

    model_config = ConfigDict(populate_by_name=True)


async def custom_request_check(request: GuardRequest) -> GuardResponse | None:
    if "debug" in request.query_params and request.query_params["debug"] == "true":
        client_host = request.client_host or "unknown"
        logger.warning(f"Blocked debug request from {client_host}")
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


def require_ipinfo_token() -> str:
    token = os.environ.get("IPINFO_TOKEN", "").strip()
    if not token:
        print(
            "IPINFO_TOKEN is not set: the country routes need a GeoIP source. "
            "Get a free token at https://ipinfo.io/signup and export IPINFO_TOKEN.",
            file=sys.stderr,
        )
        # gunicorn halts on worker exit 3; any other code is respawned
        raise SystemExit(3)
    return token


security_config = SecurityConfig(
    # IP Configuration
    blacklist=("192.168.100.0/24",),  # Example blacklisted subnet
    # Proxy Configuration
    trusted_proxies=("127.0.0.1", "10.0.0.0/8"),
    trusted_proxy_depth=2,
    trust_x_forwarded_proto=True,
    # Geographical Filtering (requires ipinfo_token OR custom implementation)
    # The country routes below need a GeoIP source: set IPINFO_TOKEN in the environment
    ipinfo_token=require_ipinfo_token(),
    # blocked_countries=["XX"],  # Example: block country code XX
    # whitelist_countries=[],  # Allow all countries by default
    # Cloud Provider Blocking
    block_cloud_providers=frozenset({"AWS", "GCP", "Azure"}),
    # User Agent Filtering
    blocked_user_agents=["badbot", "evil-crawler", "sqlmap"],
    # Rate Limiting
    enable_rate_limiting=True,
    rate_limit=30,  # 30 requests
    rate_limit_window=60,  # per 60 seconds
    # Auto-banning
    enable_ip_banning=True,
    auto_ban_threshold=5,
    auto_ban_duration=300,  # 5 minutes
    # Penetration Detection
    enable_penetration_detection=True,
    cloud_ip_refresh_interval=1800,
    log_format="json",
    # Redis Configuration
    enable_redis=True,
    redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379"),
    redis_prefix=os.environ.get("REDIS_PREFIX", "fastapi_guard:"),
    # HTTPS Enforcement
    enforce_https=False,  # Set to True in production
    # Custom Hooks
    custom_request_check=custom_request_check,
    custom_response_modifier=custom_response_modifier,
    # Authentication verifier (guard-core 3.13.0+): require_auth/api_key_auth
    # fail-closed with 401 unless a verifier resolves. This demo verifier
    # approves any presented credential and returns a principal.
    auth_verifier=demo_auth_verifier,
    # Security Headers Configuration
    security_headers={
        "enabled": True,
        # Content Security Policy
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'strict-dynamic'"],
            "style-src": ["'self'", "'unsafe-inline'"],  # Allow inline styles for demo
            "img-src": ["'self'", "data:", "https:"],
            "font-src": ["'self'", "https://fonts.gstatic.com"],
            "connect-src": ["'self'", "wss://localhost:8000"],  # WebSocket support
        },
        # HTTP Strict Transport Security
        "hsts": {
            "max_age": 31536000,  # 1 year
            "include_subdomains": True,
            "preload": False,  # Set to True for production
        },
        # Custom security headers
        "frame_options": "SAMEORIGIN",
        "referrer_policy": "strict-origin-when-cross-origin",
        "permissions_policy": (
            "accelerometer=(), camera=(), geolocation=(), "
            "gyroscope=(), magnetometer=(), microphone=(), "
            "payment=(), usb=()"
        ),
        "custom": {
            "X-App-Name": "FastAPI-Guard-Example",
            "X-Security-Contact": "security@example.com",
        },
    },
    # CORS Configuration (works alongside security headers)
    enable_cors=True,
    cors_allow_origins=["http://localhost:3000", "https://example.com"],
    cors_allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    cors_allow_headers=["*"],
    cors_allow_credentials=True,
    cors_expose_headers=["X-Total-Count"],
    cors_max_age=3600,
    # Logging Configuration
    # Console output is always enabled. File logging is optional.
    log_request_level="INFO",  # Or None to disable request logging
    log_suspicious_level="WARNING",
    custom_log_file="security.log",  # Or remove/set to None for console-only output
    # Excluded Paths
    exclude_paths=[
        "/docs",
        "/redoc",
        "/openapi.json",
        "/favicon.ico",
        "/static",
        "/basic/health",
    ],
    # Advanced Configuration
    passive_mode=False,  # Set to True for log-only mode
    # Agent Configuration (optional)
    # enable_agent=True,  # Set to True to enable telemetry
    # agent_api_key="api-test-key",
    # agent_project_id="test-project",
)


@asynccontextmanager
async def app_lifespan(app: FastAPI) -> Any:
    logger.info("FastAPI Guard Example starting up...")
    logger.info("Security features enabled:")
    logger.info(f"  - Rate limiting: {security_config.enable_rate_limiting}")
    logger.info(f"  - IP banning: {security_config.enable_ip_banning}")
    logger.info(
        f"  - Penetration detection: {security_config.enable_penetration_detection}"
    )
    logger.info(f"  - Redis: {security_config.enable_redis}")
    logger.info(f"  - Agent: {security_config.enable_agent}")
    yield
    logger.info("FastAPI Guard Example shutting down...")


# Initialize FastAPI app
# make_lifespan(app_lifespan) runs SecurityMiddleware.initialize() at ASGI startup
# (instead of deferring it to the first request) and then runs app_lifespan's own
# startup/shutdown logging; see docs/tutorial/first-steps.md
app = FastAPI(
    title="FastAPI Guard Comprehensive Example",
    description=__doc__,
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=make_lifespan(app_lifespan),
)

# Add security middleware
app.add_middleware(SecurityMiddleware, config=security_config)

# Opt-in readiness probe: GET /_guard/status reports cloud-IP/geo-IP warmup state
add_status_route(app)

# Initialize security decorator
guard_decorator = SecurityDecorator(security_config)

# Wire the decorator into the middleware so decorated-route rules actually fire
app.state.guard_decorator = guard_decorator


basic_router = APIRouter(prefix="/basic", tags=["Basic Features"])


@basic_router.get(
    "/",
    response_model=MessageResponse,
    status_code=200,
    summary="Basic Root Endpoint",
    description=(
        "Returns a simple message to verify the basic features router is operational. "
        "Subject to global rate limiting configured in the security middleware."
    ),
    responses={429: {"description": "Rate limit exceeded"}},
)
async def basic_root() -> MessageResponse:
    return MessageResponse(message="Basic features endpoint")


@basic_router.get(
    "/ip",
    response_model=IPInfoResponse,
    status_code=200,
    summary="Client IP Information",
    description=(
        "Returns detailed information about the requesting client's IP address"
        " including "
        "geolocation data. In production, this would use a geo IP handler for accurate "
        "results."
    ),
    responses={429: {"description": "Rate limit exceeded"}},
)
async def get_ip_info(request: Request) -> IPInfoResponse:
    client_ip = "unknown"
    if request.client:
        try:
            client_ip = str(ip_address(request.client.host))
        except ValueError:
            client_ip = request.client.host

    # In a real scenario, you would use the geo_ip_handler to get this info
    return IPInfoResponse(
        ip=client_ip,
        country="US",
        city="Example City",
        region="Example Region",
        is_vpn=False,
        is_cloud=False,
    )


@basic_router.get(
    "/health",
    response_model=HealthResponse,
    status_code=200,
    summary="Health Check",
    description=(
        "Returns the service health status and current timestamp. This endpoint is "
        "excluded from all security checks via the exclude_paths configuration."
    ),
)
async def health_check() -> HealthResponse:
    return HealthResponse(status="healthy", timestamp=datetime.now(timezone.utc))


@basic_router.post(
    "/echo",
    response_model=MessageResponse,
    status_code=200,
    summary="Echo Request Data",
    description=(
        "Echoes back the submitted request body along with the request headers, method,"
        " and URL. Useful for debugging and verifying that requests pass through the "
        "security middleware unmodified."
    ),
    responses={
        429: {"description": "Rate limit exceeded"},
    },
)
async def echo_request(
    request: Request,
    data: Annotated[dict[str, Any], Body(description="Request data")],
) -> MessageResponse:
    return MessageResponse(
        message="Echo response",
        details={
            "data": data,
            "headers": dict(request.headers),
            "method": request.method,
            "url": str(request.url),
        },
    )


access_router = APIRouter(prefix="/access", tags=["Access Control"])


@access_router.get(
    "/ip-whitelist",
    response_model=MessageResponse,
    status_code=200,
    summary="IP Whitelist Enforcement",
    description=(
        "Only allows access from specified IP addresses (127.0.0.1 and 10.0.0.0/8). "
        "Demonstrates per-route IP whitelist using the guard decorator."
    ),
    responses={403: {"description": "IP not in whitelist"}},
)
@guard_decorator.require_ip(whitelist=["127.0.0.1", "10.0.0.0/8"])
async def ip_whitelist_only() -> MessageResponse:
    return MessageResponse(message="Access granted from whitelisted IP")


@access_router.get(
    "/ip-blacklist",
    response_model=MessageResponse,
    status_code=200,
    summary="IP Blacklist Enforcement",
    description=(
        "Blocks access from specific IP ranges (192.168.1.0/24 and 172.16.0.0/12). "
        "Demonstrates per-route IP blacklist using the guard decorator."
    ),
    responses={403: {"description": "IP is blacklisted"}},
)
@guard_decorator.require_ip(blacklist=["192.168.1.0/24", "172.16.0.0/12"])
async def ip_blacklist_demo() -> MessageResponse:
    return MessageResponse(message="Access granted - you're not blacklisted")


@access_router.get(
    "/country-block",
    response_model=MessageResponse,
    status_code=200,
    summary="Country-Based Blocking",
    description=(
        "Blocks access from specific countries (CN, RU, KP). Requires a configured geo "
        "IP handler to resolve client IP addresses to country codes."
    ),
    responses={403: {"description": "Access denied from blocked country"}},
)
@guard_decorator.block_countries(["CN", "RU", "KP"])
async def block_specific_countries() -> MessageResponse:
    return MessageResponse(message="Access granted - your country is not blocked")


@access_router.get(
    "/country-allow",
    response_model=MessageResponse,
    status_code=200,
    summary="Country-Based Allowlist",
    description=(
        "Only allows access from specific countries (US, CA, GB, AU). All other "
        "countries are denied. Requires a configured geo IP handler."
    ),
    responses={403: {"description": "Access denied from non-allowed country"}},
)
@guard_decorator.allow_countries(["US", "CA", "GB", "AU"])
async def allow_specific_countries() -> MessageResponse:
    return MessageResponse(message="Access granted from allowed country")


@access_router.get(
    "/no-cloud",
    response_model=MessageResponse,
    status_code=200,
    summary="Block All Cloud Providers",
    description=(
        "Blocks access from all known cloud provider IP ranges including AWS, GCP, and "
        "Azure. Prevents automated access from cloud-hosted bots and scrapers."
    ),
    responses={403: {"description": "Access denied from cloud provider IP"}},
)
@guard_decorator.block_clouds()
async def block_all_clouds() -> MessageResponse:
    return MessageResponse(message="Access granted - not from cloud provider")


@access_router.get(
    "/no-aws",
    response_model=MessageResponse,
    status_code=200,
    summary="Block AWS IPs Only",
    description=(
        "Blocks access specifically from AWS IP ranges while allowing other cloud "
        "providers. Demonstrates selective cloud provider blocking."
    ),
    responses={403: {"description": "Access denied from AWS IP range"}},
)
@guard_decorator.block_clouds(["AWS"])
async def block_aws_only() -> MessageResponse:
    return MessageResponse(message="Access granted - not from AWS")


@access_router.get(
    "/bypass-demo",
    response_model=MessageResponse,
    status_code=200,
    summary="Security Check Bypass",
    description=(
        "Demonstrates bypassing specific security checks (rate_limit and ip) for "
        "a particular endpoint while keeping all other security checks active."
    ),
)
@guard_decorator.bypass(["rate_limit", "ip"])
async def bypass_specific_checks() -> MessageResponse:
    return MessageResponse(
        message="This endpoint bypasses rate limiting and IP/country/cloud checks",
        details={"bypassed_checks": ["rate_limit", "ip"]},
    )


auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


@auth_router.get(
    "/https-only",
    response_model=MessageResponse,
    status_code=200,
    summary="HTTPS Enforcement",
    description=(
        "Requires HTTPS connection to access this endpoint. Non-HTTPS requests are "
        "rejected. Demonstrates per-route HTTPS enforcement independent of the global "
        "enforce_https setting."
    ),
    responses={403: {"description": "HTTPS required"}},
)
@guard_decorator.require_https()
async def https_required_endpoint(request: Request) -> MessageResponse:
    return MessageResponse(
        message="HTTPS connection verified",
        details={"protocol": request.url.scheme},
    )


@auth_router.get(
    "/bearer-auth",
    response_model=AuthResponse,
    status_code=200,
    summary="Bearer Token Authentication",
    description=(
        "Requires a valid Bearer token in the Authorization header. Demonstrates the "
        "guard decorator's built-in bearer token authentication enforcement."
    ),
    responses={401: {"description": "Missing or invalid Bearer token"}},
)
@guard_decorator.require_auth(type="bearer")
async def bearer_authentication(
    authorization: Annotated[str | None, Header()] = None,
) -> AuthResponse:
    return AuthResponse(
        authenticated=True,
        user="example_user",
        method="bearer",
        permissions=["read", "write"],
    )


@auth_router.get(
    "/api-key",
    response_model=AuthResponse,
    status_code=200,
    summary="API Key Authentication",
    description=(
        "Requires a valid API key in the X-API-Key header. Demonstrates the guard "
        "decorator's API key authentication enforcement with a custom header name."
    ),
    responses={401: {"description": "Missing or invalid API key"}},
)
@guard_decorator.api_key_auth(header_name="X-API-Key")
async def api_key_authentication(
    x_api_key: Annotated[str | None, Header()] = None,
) -> AuthResponse:
    return AuthResponse(
        authenticated=True,
        user="api_user",
        method="api_key",
        permissions=["read"],
    )


@auth_router.get(
    "/custom-headers",
    response_model=MessageResponse,
    status_code=200,
    summary="Required Custom Headers",
    description=(
        "Requires specific headers (X-Custom-Header and X-Client-ID) to be present with"
        " exact values. Demonstrates per-route header requirements for additional"
        " request "
        "validation."
    ),
    responses={403: {"description": "Required headers missing or invalid"}},
)
@guard_decorator.require_headers(
    {"X-Custom-Header": "required-value", "X-Client-ID": "required-value"}
)
async def require_custom_headers(
    request: Request,
) -> MessageResponse:
    return MessageResponse(
        message="Required headers verified",
        details={"headers": dict(request.headers)},
    )


rate_router = APIRouter(prefix="/rate", tags=["Rate Limiting"])


@rate_router.get(
    "/custom-limit",
    response_model=MessageResponse,
    status_code=200,
    summary="Custom Rate Limit",
    description=(
        "Applies a custom per-endpoint rate limit of 5 requests per 60 seconds, "
        "overriding the global rate limit configuration. Demonstrates fine-grained rate"
        " limiting control."
    ),
    responses={429: {"description": "Rate limit exceeded (5 requests per 60 seconds)"}},
)
@guard_decorator.rate_limit(requests=5, window=60)
async def custom_rate_limit() -> MessageResponse:
    return MessageResponse(
        message="Custom rate limit endpoint",
        details={"limit": "5 requests per 60 seconds"},
    )


@rate_router.get(
    "/strict-limit",
    response_model=MessageResponse,
    status_code=200,
    summary="Strict Rate Limit",
    description=(
        "Applies an extremely strict rate limit of 1 request per 10 seconds. "
        "Demonstrates how to protect sensitive or resource-intensive endpoints from "
        "rapid successive calls."
    ),
    responses={429: {"description": "Rate limit exceeded (1 request per 10 seconds)"}},
)
@guard_decorator.rate_limit(requests=1, window=10)
async def strict_rate_limit() -> MessageResponse:
    return MessageResponse(
        message="Strict rate limit endpoint",
        details={"limit": "1 request per 10 seconds"},
    )


@rate_router.get(
    "/geo-rate-limit",
    response_model=MessageResponse,
    status_code=200,
    summary="Geographic Rate Limiting",
    description=(
        "Applies different rate limits based on the client's country of origin. US gets"
        " 100/min, CN gets 10/min, RU gets 20/min, and all others get 50/min. Requires"
        " a configured geo IP handler."
    ),
    responses={429: {"description": "Country-specific rate limit exceeded"}},
)
@guard_decorator.geo_rate_limit(
    {
        "US": (100, 60),
        "CN": (10, 60),
        "RU": (20, 60),
        "*": (50, 60),
    }
)
async def geographic_rate_limiting() -> MessageResponse:
    return MessageResponse(
        message="Geographic rate limiting applied",
        details={"description": "Rate limits vary by country"},
    )


behavior_router = APIRouter(prefix="/behavior", tags=["Behavioral Analysis"])


@behavior_router.get(
    "/usage-monitor",
    response_model=MessageResponse,
    status_code=200,
    summary="Usage Pattern Monitoring",
    description=(
        "Monitors endpoint usage and logs a warning if a single IP makes more than 10 "
        "calls within 5 minutes. Demonstrates non-blocking behavioral analysis with the"
        " 'log' action."
    ),
    responses={429: {"description": "Usage threshold exceeded"}},
)
@guard_decorator.usage_monitor(max_calls=10, window=300, action="log")
async def monitor_usage_patterns() -> MessageResponse:
    return MessageResponse(
        message="Usage monitoring active",
        details={"monitoring": "10 calls per 5 minutes"},
    )


@behavior_router.get(
    "/return-monitor/{status_code}",
    response_model=MessageResponse,
    status_code=200,
    summary="Return Pattern Monitoring",
    description=(
        "Monitors response status codes and automatically bans an IP if it receives"
        " more "
        "than 3 HTTP 404 responses within 60 seconds. Pass a status_code path parameter"
        " to simulate different responses."
    ),
    responses={
        403: {"description": "IP banned due to excessive 404 responses"},
        404: {"description": "Simulated not found response"},
    },
)
@guard_decorator.return_monitor(
    pattern="status:404", max_occurrences=3, window=60, action="ban"
)
async def monitor_return_patterns(status_code: int) -> MessageResponse:
    if status_code == 404:
        raise HTTPException(status_code=404, detail="Not found")
    return MessageResponse(message=f"Status code: {status_code}")


@behavior_router.get(
    "/suspicious-frequency",
    response_model=MessageResponse,
    status_code=200,
    summary="Suspicious Frequency Detection",
    description=(
        "Detects suspiciously high request frequency and applies throttling if requests"
        " exceed 1 every 2 seconds within a 10-second window. Demonstrates "
        "frequency-based behavioral throttling."
    ),
    responses={429: {"description": "Request frequency too high, throttled"}},
)
@guard_decorator.suspicious_frequency(max_frequency=0.5, window=10, action="throttle")
async def detect_suspicious_frequency() -> MessageResponse:
    return MessageResponse(
        message="Frequency monitoring active",
        details={"max_frequency": "1 request per 2 seconds"},
    )


@behavior_router.post(
    "/behavior-rules",
    response_model=MessageResponse,
    status_code=200,
    summary="Complex Behavioral Analysis",
    description=(
        "Applies multiple behavioral analysis rules simultaneously: frequency"
        " throttling "
        "(10 requests per 60 seconds) and return pattern banning (5 HTTP 404 responses "
        "per 60 seconds). Demonstrates composable behavior rules."
    ),
    responses={
        403: {"description": "IP banned due to return pattern violation"},
        429: {"description": "Request frequency throttled"},
    },
)
@guard_decorator.behavior_analysis(
    [
        BehaviorRule(rule_type="frequency", threshold=10, window=60, action="throttle"),
        BehaviorRule(
            rule_type="return_pattern",
            pattern="status:404",
            threshold=5,
            window=60,
            action="ban",
        ),
    ]
)
async def complex_behavior_analysis() -> MessageResponse:
    return MessageResponse(
        message="Complex behavior analysis active",
        details={"rules": ["frequency", "return_pattern"]},
    )


headers_router = APIRouter(prefix="/headers", tags=["Security Headers"])


@headers_router.get(
    "/",
    response_model=MessageResponse,
    status_code=200,
    summary="Security Headers Overview",
    description=(
        "Lists all security headers applied to every response by the middleware, "
        "including CSP, HSTS, X-Frame-Options, and custom headers. Check browser "
        "developer tools to inspect the actual response headers."
    ),
)
async def security_headers_info() -> MessageResponse:
    return MessageResponse(
        message="All responses include comprehensive security headers",
        details={
            "headers": [
                "X-Content-Type-Options: nosniff",
                "X-Frame-Options: SAMEORIGIN",
                "X-XSS-Protection: 1; mode=block",
                "Strict-Transport-Security: max-age=31536000",
                "Content-Security-Policy: default-src 'self'",
                "Referrer-Policy: strict-origin-when-cross-origin",
                "Permissions-Policy: accelerometer=(), camera=(), ...",
                "X-App-Name: FastAPI-Guard-Example",
                "X-Security-Contact: security@example.com",
            ],
            "note": "Check browser developer tools to see all headers",
        },
    )


@headers_router.get(
    "/test-page",
    response_class=HTMLResponse,
    status_code=200,
    summary="CSP Test Page",
    description=(
        "Serves an HTML page that demonstrates Content Security Policy in action. The "
        "page includes inline scripts and styles that may be blocked depending on CSP "
        "configuration. Check the browser console for CSP violation reports."
    ),
)
async def security_headers_test_page() -> str:
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Headers Demo</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .header {
                color: #333;
                border-bottom: 2px solid #007acc;
                padding-bottom: 10px;
            }
            .demo-box {
                background: white;
                padding: 20px;
                margin: 20px 0;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }
            .warning {
                color: #d63384;
                font-weight: bold;
            }
            .success {
                color: #198754;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1 class="header">FastAPI Guard Security Headers Demo</h1>

        <div class="demo-box">
            <h2>Content Security Policy Test</h2>
            <p>This page tests various CSP restrictions:</p>
            <ul>
                <li><b>Inline Styles:</b> <span id="style-test">Styled</span></li>
                <li><b>Inline Scripts:</b> <span id="script-test">Waiting...</span></li>
                <li><strong>External Resources:</strong> Limited by CSP directives</li>
            </ul>
        </div>

        <div class="demo-box">
            <h2>Security Headers Applied</h2>
            <p>Check the <strong>Network</strong> tab in Developer Tools to see:</p>
            <ul>
                <li>X-Content-Type-Options: nosniff</li>
                <li>X-Frame-Options: SAMEORIGIN</li>
                <li>X-XSS-Protection: 1; mode=block</li>
                <li>Strict-Transport-Security</li>
                <li>Content-Security-Policy</li>
                <li>Custom headers from FastAPI Guard</li>
            </ul>
        </div>

        <div class="demo-box">
            <h2>CSP Violation Testing</h2>
            <button onclick="testInlineScript()">Test Inline Script</button>
            <button onclick="testEval()">Test eval() Function</button>
            <p id="test-results"></p>
            <p><em>Check browser console for CSP violation reports</em></p>
        </div>

        <script>
            console.log("Inline script executed - CSP allows inline scripts");
            var el = document.getElementById('script-test');
            el.textContent = 'Script executed!';
            document.getElementById('script-test').className = 'success';

            function testInlineScript() {
                try {
                    document.getElementById('test-results').innerHTML =
                        '<span class="success">Inline event handlers work</span>';
                } catch (e) {
                    document.getElementById('test-results').innerHTML =
                        '<span class="warning">Blocked: ' + e.message + '</span>';
                }
            }

            function testEval() {
                try {
                    eval('console.log("eval() executed")');
                    document.getElementById('test-results').innerHTML =
                        '<span class="warning">eval() allowed!</span>';
                } catch (e) {
                    document.getElementById('test-results').innerHTML =
                        '<span class="success">Blocked: ' + e.message + '</span>';
                }
            }

            try {
                const script = document.createElement('script');
                script.textContent = 'console.log("Dynamic script executed")';
                document.head.appendChild(script);
            } catch (e) {
                console.log('Dynamic script blocked:', e.message);
            }
        </script>
    </body>
    </html>
    """


@headers_router.post(
    "/csp-report",
    response_model=MessageResponse,
    status_code=200,
    summary="CSP Violation Report Receiver",
    description=(
        "Receives Content Security Policy violation reports sent by browsers. Configure"
        " the CSP report-uri directive to point to this endpoint for monitoring policy "
        "violations in production."
    ),
    responses={422: {"description": "Invalid CSP report format"}},
)
async def receive_csp_report(report: CspReportWrapper) -> MessageResponse:
    violation = report.csp_report

    logger.warning(
        f"CSP Violation: {violation.violated_directive or 'unknown'} "
        f"blocked {violation.blocked_uri or 'unknown'} "
        f"on {violation.document_uri or 'unknown'}"
    )

    return MessageResponse(
        message="CSP violation report received",
        details={
            "violated_directive": violation.violated_directive,
            "blocked_uri": violation.blocked_uri,
            "source_file": violation.source_file,
            "line_number": violation.line_number,
        },
    )


@headers_router.get(
    "/frame-test",
    response_class=HTMLResponse,
    status_code=200,
    summary="X-Frame-Options Test Page",
    description=(
        "Serves an HTML page that demonstrates the X-Frame-Options header behavior. The"
        " page has SAMEORIGIN framing policy, allowing iframe embedding from the same "
        "origin but blocking external sites."
    ),
)
async def frame_test() -> str:
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Frame Options Test</title></head>
    <body>
        <h1>X-Frame-Options Test</h1>
        <p>This page has X-Frame-Options: SAMEORIGIN header.</p>
        <p>Embeddable from same origin, blocked from external sites.</p>
        <div style="margin: 20px; padding: 20px; border: 1px solid #ccc;">
            <h3>Try embedding this page:</h3>
            <code>&lt;iframe src="/headers/frame-test"&gt;&lt;/iframe&gt;</code>
            <p>Should work from same origin<br>
               Should be blocked from external sites</p>
        </div>
    </body>
    </html>
    """


@headers_router.get(
    "/hsts-info",
    response_model=MessageResponse,
    status_code=200,
    summary="HSTS Configuration Info",
    description=(
        "Returns details about the HTTP Strict Transport Security configuration "
        "including max-age, includeSubDomains, and preload settings. HSTS forces "
        "browsers to use HTTPS for all future requests to this domain."
    ),
)
async def hsts_info() -> MessageResponse:
    return MessageResponse(
        message="HSTS (HTTP Strict Transport Security) is active",
        details={
            "max_age": "31536000 seconds (1 year)",
            "include_subdomains": True,
            "preload": False,
            "description": "Forces HTTPS connections for improved security",
            "note": "In production, enable preload and submit to HSTS preload list",
        },
    )


@headers_router.get(
    "/security-analysis",
    response_model=MessageResponse,
    status_code=200,
    summary="Request Security Analysis",
    description=(
        "Analyzes the incoming request's security-relevant headers (user-agent, origin,"
        " referer, x-forwarded-for) and returns a summary of active security features "
        "along with production recommendations."
    ),
)
async def security_analysis(request: Request) -> MessageResponse:
    return MessageResponse(
        message="Security analysis of current request",
        details={
            "request_headers": {
                "user_agent": request.headers.get("user-agent", "Not provided"),
                "origin": request.headers.get("origin", "Not provided"),
                "referer": request.headers.get("referer", "Not provided"),
                "x_forwarded_for": request.headers.get(
                    "x-forwarded-for", "Not provided"
                ),
            },
            "security_features": [
                "Content-Type sniffing protection (X-Content-Type-Options)",
                "Clickjacking protection (X-Frame-Options)",
                "XSS filtering (X-XSS-Protection)",
                "HTTPS enforcement (Strict-Transport-Security)",
                "Content restrictions (Content-Security-Policy)",
                "Referrer policy control",
                "Feature permissions control",
                "Custom security headers",
            ],
            "recommendations": [
                "Always use HTTPS in production",
                "Regularly review and tighten CSP directives",
                "Monitor CSP violation reports",
                "Consider HSTS preload for production domains",
                "Test security headers with online tools",
            ],
        },
    )


content_router = APIRouter(prefix="/content", tags=["Content Filtering"])


@content_router.get(
    "/no-bots",
    response_model=MessageResponse,
    status_code=200,
    summary="Bot User Agent Blocking",
    description=(
        "Blocks requests from user agents containing 'bot', 'crawler', 'spider', or "
        "'scraper'. Demonstrates per-route user agent filtering to prevent automated "
        "access."
    ),
    responses={403: {"description": "Bot user agent detected and blocked"}},
)
@guard_decorator.block_user_agents(["bot", "crawler", "spider", "scraper"])
async def block_bots() -> MessageResponse:
    return MessageResponse(message="Human users only - bots blocked")


@content_router.post(
    "/json-only",
    response_model=MessageResponse,
    status_code=200,
    summary="JSON Content Type Filter",
    description=(
        "Only accepts requests with Content-Type: application/json. All other content "
        "types are rejected. Demonstrates per-route content type enforcement."
    ),
    responses={415: {"description": "Unsupported content type"}},
)
@guard_decorator.content_type_filter(["application/json"])
async def json_content_only(data: dict[str, Any]) -> MessageResponse:
    return MessageResponse(
        message="JSON content received",
        details={"data": data},
    )


@content_router.post(
    "/size-limit",
    response_model=MessageResponse,
    status_code=200,
    summary="Request Size Limit",
    description=(
        "Limits the request body size to 100KB. Requests exceeding this limit are "
        "rejected before processing. Demonstrates per-route request size enforcement to"
        " prevent large payload attacks."
    ),
    responses={413: {"description": "Request body exceeds 100KB size limit"}},
)
@guard_decorator.max_request_size(1024 * 100)
async def limited_upload_size(data: dict[str, Any]) -> MessageResponse:
    return MessageResponse(
        message="Data received within size limit",
        details={"size_limit": "100KB"},
    )


@content_router.get(
    "/referrer-check",
    response_model=MessageResponse,
    status_code=200,
    summary="Referrer Validation",
    description=(
        "Requires the Referer header to match one of the allowed domains (example.com"
        " or "
        "app.example.com). Prevents access from unauthorized referring sites and helps "
        "mitigate CSRF-like attacks."
    ),
    responses={403: {"description": "Invalid or missing referrer"}},
)
@guard_decorator.require_referrer(["https://example.com", "https://app.example.com"])
async def check_referrer(request: Request) -> MessageResponse:
    referrer = request.headers.get("referer", "No referrer")
    return MessageResponse(
        message="Valid referrer",
        details={"referrer": referrer},
    )


async def custom_validator(request: GuardRequest) -> GuardResponse | None:
    user_agent = request.headers.get("user-agent", "").lower()
    if "suspicious-pattern" in user_agent:
        return StarletteGuardResponse(
            JSONResponse(
                status_code=403,
                content={"detail": "Suspicious user agent detected"},
            )
        )
    return None


@content_router.get(
    "/custom-validation",
    response_model=MessageResponse,
    status_code=200,
    summary="Custom Request Validation",
    description=(
        "Applies a custom validator function that inspects the request before "
        "processing. The example validator checks the user agent for suspicious"
        " patterns "
        "and rejects matching requests."
    ),
    responses={403: {"description": "Custom validation failed"}},
)
@guard_decorator.custom_validation(custom_validator)
async def custom_content_validation() -> MessageResponse:
    return MessageResponse(
        message="Custom validation passed",
        details={"validator": "custom_validator"},
    )


advanced_router = APIRouter(prefix="/advanced", tags=["Advanced Features"])


@advanced_router.get(
    "/business-hours",
    response_model=MessageResponse,
    status_code=200,
    summary="Business Hours Access Control",
    description=(
        "Restricts access to business hours only (09:00-17:00 UTC). Requests outside "
        "this time window are rejected. Demonstrates time-based access control for "
        "sensitive endpoints."
    ),
    responses={
        403: {"description": "Access denied outside business hours (09:00-17:00 UTC)"}
    },
)
@guard_decorator.time_window(start_time="09:00", end_time="17:00", timezone="UTC")
async def business_hours_only() -> MessageResponse:
    return MessageResponse(
        message="Access granted during business hours",
        details={"hours": "09:00-17:00 UTC"},
    )


@advanced_router.get(
    "/weekend-only",
    response_model=MessageResponse,
    status_code=200,
    summary="Weekend Access Control",
    description=(
        "Demonstrates time-window-based access control configured for all-day access."
        " In "
        "practice, this would need custom logic to restrict access to weekends only."
    ),
    responses={403: {"description": "Access denied outside configured time window"}},
)
@guard_decorator.time_window(start_time="00:00", end_time="23:59", timezone="UTC")
async def weekend_endpoint() -> MessageResponse:
    return MessageResponse(
        message="Weekend access endpoint",
        details={"note": "Implement weekend check in time_window"},
    )


@advanced_router.post(
    "/honeypot",
    response_model=MessageResponse,
    status_code=200,
    summary="Honeypot Bot Detection",
    description=(
        "Detects bots by checking for hidden honeypot fields (honeypot_field, "
        "trap_input, hidden_field) in the request body. Legitimate users with proper "
        "forms will never fill these fields, but automated bots typically do."
    ),
    responses={403: {"description": "Bot detected via honeypot field"}},
)
@guard_decorator.honeypot_detection(["honeypot_field", "trap_input", "hidden_field"])
async def honeypot_detection(payload: TestPayload) -> MessageResponse:
    return MessageResponse(
        message="Human user verified",
        details={"honeypot_status": "clean"},
    )


@advanced_router.get(
    "/suspicious-patterns",
    response_model=MessageResponse,
    status_code=200,
    summary="Enhanced Suspicious Pattern Detection",
    description=(
        "Enables enhanced suspicious pattern detection for this endpoint. The"
        " middleware "
        "analyzes query parameters and request patterns for SQL injection, XSS, path "
        "traversal, and other attack signatures."
    ),
    responses={403: {"description": "Suspicious pattern detected in request"}},
)
@guard_decorator.suspicious_detection(enabled=True)
async def detect_suspicious_patterns(
    query: str = Query(None, description="Test query parameter"),
) -> MessageResponse:
    return MessageResponse(
        message="No suspicious patterns detected",
        details={"query": query},
    )


admin_router = APIRouter(prefix="/admin", tags=["Admin & Utilities"])


@admin_router.post(
    "/unban-ip",
    response_model=MessageResponse,
    status_code=200,
    summary="Unban IP Address",
    description=(
        "Removes a specific IP address from the ban list. Restricted to localhost"
        " access "
        "only. The unban operation runs as a background task to avoid blocking the "
        "response."
    ),
    responses={
        403: {"description": "Access denied, admin endpoint restricted to localhost"}
    },
)
@guard_decorator.require_ip(whitelist=["127.0.0.1"])
async def unban_ip_address(
    ip: Annotated[str, Body(description="IP address to unban")],
    background_tasks: BackgroundTasks,
) -> MessageResponse:
    background_tasks.add_task(logger.info, f"Unbanning IP: {ip}")
    return MessageResponse(
        message=f"IP {ip} has been unbanned",
        details={"action": "unban", "ip": ip},
    )


@admin_router.get(
    "/stats",
    response_model=StatsResponse,
    status_code=200,
    summary="Security Statistics",
    description=(
        "Returns comprehensive security statistics including total requests, blocked "
        "requests, banned IPs, rate-limited IPs, suspicious activities, and active "
        "security rules. Restricted to localhost access only."
    ),
    responses={
        403: {"description": "Access denied, admin endpoint restricted to localhost"}
    },
)
@guard_decorator.require_ip(whitelist=["127.0.0.1"])
async def get_security_stats() -> StatsResponse:
    return StatsResponse(
        total_requests=1500,
        blocked_requests=75,
        banned_ips=["192.168.1.100", "10.0.0.50"],
        rate_limited_ips={"192.168.1.200": 5, "172.16.0.10": 3},
        suspicious_activities=[
            {
                "ip": "192.168.1.100",
                "reason": "SQL injection attempt",
                "timestamp": datetime.now(timezone.utc),
            },
            {
                "ip": "10.0.0.50",
                "reason": "Rapid requests",
                "timestamp": datetime.now(timezone.utc),
            },
        ],
        active_rules={
            "rate_limit": 30,
            "rate_window": 60,
            "auto_ban_threshold": 5,
            "blocked_countries": ["XX"],
            "blocked_clouds": ["AWS", "GCP", "Azure"],
        },
    )


@admin_router.post(
    "/clear-cache",
    response_model=MessageResponse,
    status_code=200,
    summary="Clear Security Caches",
    description=(
        "Clears all security-related caches including rate limit counters, IP ban "
        "records, and geo lookup cache. Restricted to localhost access only. Useful for"
        " resetting state during testing or after configuration changes."
    ),
    responses={
        403: {"description": "Access denied, admin endpoint restricted to localhost"}
    },
)
@guard_decorator.require_ip(whitelist=["127.0.0.1"])
async def clear_security_cache() -> MessageResponse:
    return MessageResponse(
        message="Security caches cleared",
        details={"cleared": ["rate_limit_cache", "ip_ban_cache", "geo_cache"]},
    )


@admin_router.put(
    "/emergency-mode",
    response_model=MessageResponse,
    status_code=200,
    summary="Toggle Emergency Mode",
    description=(
        "Enables or disables emergency mode which blocks all incoming requests except "
        "those from whitelisted IPs. Restricted to localhost access only. Use this "
        "during active attacks or security incidents."
    ),
    responses={
        403: {"description": "Access denied, admin endpoint restricted to localhost"}
    },
)
@guard_decorator.require_ip(whitelist=["127.0.0.1"])
async def toggle_emergency_mode(
    enable: Annotated[bool, Body(description="Enable or disable emergency mode")],
) -> MessageResponse:
    mode = "enabled" if enable else "disabled"
    return MessageResponse(
        message=f"Emergency mode {mode}",
        details={"emergency_mode": enable, "timestamp": datetime.now(timezone.utc)},
    )


@admin_router.get(
    "/cloud-status",
    response_model=MessageResponse,
    status_code=200,
    summary="Cloud Provider IP Range Status",
    description=(
        "Returns per-provider cloud IP range refresh status including the configured "
        "refresh interval and last update timestamps for each provider."
    ),
    responses={
        403: {"description": "Access denied, admin endpoint restricted to localhost"}
    },
)
@guard_decorator.require_ip(whitelist=["127.0.0.1"])
async def cloud_provider_status() -> MessageResponse:
    last_updated = {}
    # `guard.cloud_handler` is the default app's; this app's own manager:
    for provider, dt in cloud_handler_for(security_config).last_updated.items():
        last_updated[provider] = dt.isoformat() if dt else None
    return MessageResponse(
        message="Cloud provider IP range status",
        details={
            "refresh_interval": security_config.cloud_ip_refresh_interval,
            "providers": last_updated,
        },
    )


test_router = APIRouter(prefix="/test", tags=["Security Testing"])


@test_router.post(
    "/xss-test",
    response_model=MessageResponse,
    status_code=200,
    summary="XSS Detection Test",
    description=(
        "Accepts a payload string to test the middleware's cross-site scripting (XSS) "
        "detection capabilities. Malicious payloads containing script tags or event "
        "handlers should be caught and blocked by the penetration detection engine."
    ),
    responses={403: {"description": "XSS attack pattern detected and blocked"}},
)
async def test_xss_detection(
    payload: Annotated[str, Body(description="XSS test payload")],
) -> MessageResponse:
    return MessageResponse(
        message="XSS test payload processed",
        details={"payload": payload, "detected": False},
    )


@test_router.post(
    "/sql-injection",
    response_model=MessageResponse,
    status_code=200,
    summary="SQL Injection Detection Test",
    description=(
        "Accepts a query parameter to test the middleware's SQL injection detection "
        "capabilities. Payloads containing SQL keywords like UNION SELECT, DROP TABLE, "
        "or OR 1=1 should be caught and blocked."
    ),
    responses={403: {"description": "SQL injection pattern detected and blocked"}},
)
async def test_sql_injection(
    query: str = Query(..., description="SQL injection test"),
) -> MessageResponse:
    return MessageResponse(
        message="SQL injection test processed",
        details={"query": query, "detected": False},
    )


@test_router.get(
    "/path-traversal/{file_path:path}",
    response_model=MessageResponse,
    status_code=200,
    summary="Path Traversal Detection Test",
    description=(
        "Accepts a file path parameter to test the middleware's path traversal"
        " detection "
        "capabilities. Paths containing sequences like ../ or attempting to access "
        "/etc/passwd should be caught and blocked."
    ),
    responses={403: {"description": "Path traversal pattern detected and blocked"}},
)
async def test_path_traversal(file_path: str) -> MessageResponse:
    return MessageResponse(
        message="Path traversal test",
        details={"path": file_path, "detected": False},
    )


@test_router.post(
    "/command-injection",
    response_model=MessageResponse,
    status_code=200,
    summary="Command Injection Detection Test",
    description=(
        "Accepts a command string to test the middleware's OS command injection "
        "detection capabilities. Payloads containing shell metacharacters like ;, |, or"
        " backticks should be caught and blocked."
    ),
    responses={403: {"description": "Command injection pattern detected and blocked"}},
)
async def test_command_injection(
    command: Annotated[str, Body(description="Command injection test")],
) -> MessageResponse:
    return MessageResponse(
        message="Command injection test processed",
        details={"command": command, "detected": False},
    )


@test_router.post(
    "/mixed-attack",
    response_model=MessageResponse,
    status_code=200,
    summary="Mixed Attack Vector Test",
    description=(
        "Accepts a structured payload with multiple fields to test simultaneous "
        "detection of XSS, SQL injection, path traversal, command injection, and "
        "honeypot triggers. Demonstrates the middleware's ability to detect combined "
        "attack vectors."
    ),
    responses={
        403: {"description": "One or more attack patterns detected and blocked"}
    },
)
async def test_mixed_attack(payload: TestPayload) -> MessageResponse:
    return MessageResponse(
        message="Mixed attack test processed",
        details={
            "xss_test": payload.input,
            "sql_test": payload.query,
            "path_test": payload.path,
            "cmd_test": payload.cmd,
            "honeypot": payload.honeypot_field,
        },
    )


@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket, _: None = Depends(guard_websocket)
) -> None:
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(f"Echo: {data}")

            if data == "status":
                await websocket.send_json(
                    {
                        "type": "status",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "security": "active",
                    }
                )
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")


@app.get(
    "/",
    response_model=MessageResponse,
    status_code=200,
    summary="API Root",
    description=(
        "Returns API information including the version, list of available security "
        "features, documentation URL, and a route map of all available endpoints "
        "organized by feature category."
    ),
    responses={429: {"description": "Rate limit exceeded"}},
)
async def root() -> MessageResponse:
    return MessageResponse(
        message="FastAPI Guard Comprehensive Example API",
        details={
            "version": "2.0.0",
            "features": [
                "IP filtering",
                "Country blocking",
                "Cloud provider blocking",
                "Rate limiting",
                "Security headers",
                "Behavioral analysis",
                "Content filtering",
                "Authentication",
                "Advanced security features",
            ],
            "documentation": "/docs",
            "routes": {
                "/basic": "Basic security features",
                "/access": "Access control demonstrations",
                "/auth": "Authentication examples",
                "/rate": "Rate limiting examples",
                "/behavior": "Behavioral analysis",
                "/headers": "Security headers demonstration",
                "/content": "Content filtering",
                "/advanced": "Advanced features",
                "/admin": "Admin utilities",
                "/test": "Security testing",
                "/ws": "WebSocket endpoint",
            },
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            detail=exc.detail,
            error_code=f"HTTP_{exc.status_code}",
        ).model_dump(mode="json"),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            detail="Internal server error",
            error_code="INTERNAL_ERROR",
        ).model_dump(mode="json"),
    )


app.include_router(basic_router)
app.include_router(access_router)
app.include_router(auth_router)
app.include_router(rate_router)
app.include_router(behavior_router)
app.include_router(headers_router)
app.include_router(content_router)
app.include_router(advanced_router)
app.include_router(admin_router)
app.include_router(test_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
