import logging
import time
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Body, HTTPException
from guard_core.handlers.cloud_handler import cloud_handler_for
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.ratelimit_handler import RateLimitManager

from app.models import MessageResponse, StatsResponse
from app.security import guard, security_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin & Utilities"])

DYNAMIC_RULES_OWN_EMERGENCY_MODE = (
    "this app takes emergency mode from the dashboard's dynamic rules; a local "
    "switch would be reverted at the next rule update"
)


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
        "Returns the banned IPs, the rate limit windows in use and the active "
        "rules, read from the guard engine. The engine keeps no request counters, "
        "so none are reported. Restricted to localhost."
    ),
    responses={403: {"description": "Not authorized (non-localhost IP)"}},
)
@guard.require_ip(whitelist=["127.0.0.1"])
async def get_security_stats() -> StatsResponse:
    """Reads this process's ban table (IPBanManager.banned_ips), its rate limit
    windows (RateLimitManager.request_timestamps) and the SecurityConfig rules.
    The engine keeps no request counters, so none are reported."""
    now = time.time()
    return StatsResponse(
        banned_ips=sorted(
            ip
            for ip, expiry in ip_ban_manager_for(security_config).banned_ips.items()
            if expiry > now
        ),
        rate_limit_windows={
            key: len(window)
            for key, window in RateLimitManager(
                security_config
            ).request_timestamps.items()
            if window
        },
        active_rules={
            "rate_limit": security_config.rate_limit,
            "rate_limit_window": security_config.rate_limit_window,
            "auto_ban_threshold": security_config.auto_ban_threshold,
            "blocked_countries": list(security_config.blocked_countries),
            "block_cloud_providers": sorted(
                security_config.block_cloud_providers or ()
            ),
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
        "Switches emergency mode on this process: only the emergency whitelist (plus "
        "127.0.0.1) is admitted and everyone else gets 503. The sources of emergency "
        "mode are SecurityConfig.emergency_mode at startup and a dynamic rule from "
        "the dashboard at runtime; this route changes this process only, so "
        "multi-worker deployments use the dashboard's dynamic rule. Answers 409 when "
        "dynamic rules are enabled and 400 when the body is not a boolean. "
        "Restricted to localhost."
    ),
    responses={403: {"description": "Not authorized (non-localhost IP)"}},
)
@guard.require_ip(whitelist=["127.0.0.1"])
async def toggle_emergency_mode(
    enable: Annotated[Any, Body(description="true or false")] = None,
) -> MessageResponse:
    """Switches emergency mode on this process through SecurityConfig.

    Emergency mode has two sources: SecurityConfig.emergency_mode set at startup,
    or a dynamic rule from the dashboard at runtime. This route is the local
    switch: it changes this process only, so a multi-worker deployment uses the
    dashboard's dynamic rule. While emergency mode is on only emergency_whitelist
    is admitted, so enabling adds 127.0.0.1 to keep this admin route reachable.
    """
    if not isinstance(enable, bool):
        raise HTTPException(status_code=400, detail="The body must be true or false")
    if security_config.enable_dynamic_rules:
        raise HTTPException(status_code=409, detail=DYNAMIC_RULES_OWN_EMERGENCY_MODE)
    if enable and "127.0.0.1" not in security_config.emergency_whitelist:
        security_config.emergency_whitelist = [
            *security_config.emergency_whitelist,
            "127.0.0.1",
        ]
    security_config.emergency_mode = enable
    state = "enabled" if security_config.emergency_mode else "disabled"
    return MessageResponse(
        message=f"Emergency mode {state}",
        details={
            "emergency_mode": security_config.emergency_mode,
            "emergency_whitelist": list(security_config.emergency_whitelist),
            "timestamp": datetime.now(timezone.utc),
        },
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
