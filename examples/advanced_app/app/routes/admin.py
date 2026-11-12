import logging
from datetime import datetime, timezone
from ipaddress import ip_address

from fastapi import APIRouter, BackgroundTasks, Body, HTTPException
from guard_core.handlers.cloud_handler import cloud_handler_for
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.ratelimit_handler import RateLimitManager

from app.models import MessageResponse, StatsResponse
from app.security import guard, security_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin & Utilities"])


@router.post(
    "/unban-ip",
    response_model=MessageResponse,
    status_code=200,
    summary="Unban IP Address",
    description=(
        "Removes an IP address from the ban list. Restricted to requests from localhost"
        "only."
    ),
    responses={403: {"description": "Not authorized (non-localhost IP)"}},
)
@guard.require_ip(whitelist=["127.0.0.1"])
async def unban_ip_address(
    ip: str = Body(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),  # noqa: B008
) -> MessageResponse:
    try:
        address = str(ip_address(ip.strip()))
    except ValueError:
        raise HTTPException(status_code=400, detail="Not an IP address") from None
    # The module-level `ip_ban_manager` is the default app's. This app's own:
    await ip_ban_manager_for(security_config).unban_ip(address)
    background_tasks.add_task(logger.info, f"Unbanning IP: {address}")
    return MessageResponse(
        message=f"IP {address} has been unbanned",
        details={"action": "unban", "ip": address},
    )


@router.get(
    "/stats",
    response_model=StatsResponse,
    status_code=200,
    summary="Security Statistics",
    description=(
        "Returns security statistics including total requests, blocked requests, banned"
        "IPs, rate-limited IPs, and active rules. Restricted to localhost."
    ),
    responses={403: {"description": "Not authorized (non-localhost IP)"}},
)
@guard.require_ip(whitelist=["127.0.0.1"])
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


@router.post(
    "/clear-cache",
    response_model=MessageResponse,
    status_code=200,
    summary="Clear Security Caches",
    description=(
        "Clears every IP ban (operator bans included) and every rate limit window"
        " for this app's Redis prefix. Restricted to localhost."
    ),
    responses={403: {"description": "Not authorized (non-localhost IP)"}},
)
@guard.require_ip(whitelist=["127.0.0.1"])
async def clear_security_cache() -> MessageResponse:
    """Clears all bans and rate limit windows for this app's Redis prefix."""
    await ip_ban_manager_for(security_config).reset()
    await RateLimitManager(security_config).reset()
    return MessageResponse(
        message="Security caches cleared",
        details={"cleared": ["ip_bans", "rate_limit_windows"]},
    )


@router.put(
    "/emergency-mode",
    response_model=MessageResponse,
    status_code=200,
    summary="Toggle Emergency Mode",
    description=(
        "Enables or disables emergency lockdown mode. When active, all non-whitelisted"
        "traffic is blocked. Restricted to localhost."
    ),
    responses={403: {"description": "Not authorized (non-localhost IP)"}},
)
@guard.require_ip(whitelist=["127.0.0.1"])
async def toggle_emergency_mode(
    enable: bool = Body(...),
) -> MessageResponse:
    mode = "enabled" if enable else "disabled"
    return MessageResponse(
        message=f"Emergency mode {mode}",
        details={"emergency_mode": enable, "timestamp": datetime.now(timezone.utc)},
    )


@router.get(
    "/cloud-status",
    response_model=MessageResponse,
    status_code=200,
    summary="Cloud Provider IP Range Status",
    description=(
        "Returns per-provider cloud IP range refresh status including the configured"
        "refresh interval and last update timestamps for each provider."
    ),
    responses={403: {"description": "Not authorized (non-localhost IP)"}},
)
@guard.require_ip(whitelist=["127.0.0.1"])
async def cloud_provider_status() -> MessageResponse:
    last_updated = {}
    for provider, dt in cloud_handler_for(security_config).last_updated.items():
        last_updated[provider] = dt.isoformat() if dt else None
    return MessageResponse(
        message="Cloud provider IP range status",
        details={
            "refresh_interval": security_config.cloud_ip_refresh_interval,
            "providers": last_updated,
        },
    )
