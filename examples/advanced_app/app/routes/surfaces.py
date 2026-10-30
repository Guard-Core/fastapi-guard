import asyncio
import os
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Body, Request
from fastapi.responses import JSONResponse, StreamingResponse
from guard_core import endpoint_rate_limit_key_problems
from guard_core.handlers.behavior_handler import BehaviorTracker
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for

from app.security import guard, security_config
from guard import (
    BehaviorRule,
    BoundedBodyReader,
    BoundedResponseBodyReader,
    SecurityHeadersManager,
    check_ip_access,
    is_ip_allowed,
    security_headers_manager,
)
from guard.adapters import StarletteGuardRequest, StarletteGuardResponse
from guard.lifespan import _built_security_middleware

router = APIRouter(tags=["Surfaces"])
blocks = APIRouter(prefix="/blocks", tags=["Building Blocks"])


# The five-method route (innermost, so registered first) answers every request and a
# 405 with the full Allow list: Starlette's 405 names only the first route that matches
# the path. The per-method routes only document it: FastAPI derives an api_route's
# operation id from its first method, so one five-method entry would repeat an id.
@router.get("/methods/resource", summary="Echoes the HTTP method the guard let through")
@router.post(
    "/methods/resource", summary="Echoes the HTTP method the guard let through"
)
@router.put("/methods/resource", summary="Echoes the HTTP method the guard let through")
@router.patch(
    "/methods/resource", summary="Echoes the HTTP method the guard let through"
)
@router.delete(
    "/methods/resource", summary="Echoes the HTTP method the guard let through"
)
@router.api_route(
    "/methods/resource",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    include_in_schema=False,
)
async def method_echo(request: Request) -> dict[str, str]:
    return {"method": request.method}


@router.get("/stream/numbers", summary="A streamed response")
async def stream_numbers() -> StreamingResponse:
    async def chunks() -> AsyncIterator[bytes]:
        for number in range(5):
            yield f"line-{number}\n".encode()
            await asyncio.sleep(0.01)

    return StreamingResponse(chunks(), media_type="text/plain")


@router.get("/surfaces/introspect", summary="Middleware introspection helpers")
async def introspect(request: Request) -> dict[str, Any]:
    middleware = _built_security_middleware(request.app)
    assert middleware is not None, "the built SecurityMiddleware is in the stack"
    return {
        "allowed_methods": list(middleware.allowed_methods("/methods/resource")),
        "static_route_prefixes": list(middleware.static_route_prefixes()),
        "initialization_status": middleware.get_initialization_status(),
        "agent_stats_is_dict": isinstance(middleware.agent_stats, dict),
    }


@router.get("/surfaces/worker", summary="The pid of the worker that served this")
async def worker() -> dict[str, int]:
    return {"pid": os.getpid()}


@blocks.get("/ip-access")
async def ip_access(dashed_ip: str) -> dict[str, Any]:
    # A dotted private IP in a query value is itself an SSRF match, so the address
    # arrives dashed.
    ip = dashed_ip.replace("-", ".")
    verdict = await check_ip_access(ip, security_config)
    return {
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "is_ip_allowed": await is_ip_allowed(ip, security_config),
    }


@blocks.get("/endpoint-key-problems")
async def endpoint_key_problems(key: str) -> dict[str, list[str]]:
    # A literal dot segment in a query value is itself a traversal match.
    endpoint = key.replace("DOTDOT", "..")
    return {"problems": endpoint_rate_limit_key_problems({endpoint: (1, 1)})}


@blocks.get("/security-headers")
async def security_headers() -> dict[str, Any]:
    return {
        "singleton": isinstance(security_headers_manager, SecurityHeadersManager),
        "headers": security_headers_manager.resolve_headers(security_config),
    }


@blocks.get("/behavior")
@guard.require_ip(whitelist=["127.0.0.1"])
async def behavior(request: Request) -> dict[str, Any]:
    rule = BehaviorRule("usage", threshold=2, window=60, action="log")
    tracker = BehaviorTracker(security_config)
    first = await tracker.track_endpoint_usage("blocks-behavior", "203.0.113.9", rule)
    second = await tracker.track_endpoint_usage("blocks-behavior", "203.0.113.9", rule)
    third = await tracker.track_endpoint_usage("blocks-behavior", "203.0.113.9", rule)
    return {
        "rule_id_is_stable": rule.matched_rule_id()
        == BehaviorRule(
            "usage", threshold=2, window=60, action="log"
        ).matched_rule_id(),
        "threshold_crossed_on": [first, second, third],
        "request_is_bounded_body_reader": isinstance(
            StarletteGuardRequest(request), BoundedBodyReader
        ),
        "response_is_bounded_response_reader": isinstance(
            StarletteGuardResponse(JSONResponse({})), BoundedResponseBodyReader
        ),
    }


@blocks.get("/rate-limit")
@guard.require_ip(whitelist=["127.0.0.1"])
async def rate_limit(request: Request) -> dict[str, bool]:
    manager = RateLimitManager(security_config)

    async def refuse(status_code: int, message: str) -> StarletteGuardResponse:
        return StarletteGuardResponse(
            JSONResponse({"detail": message}, status_code=status_code)
        )

    refusal = await manager.check_rate_limit(
        StarletteGuardRequest(request),
        "203.0.113.77",
        refuse,
        endpoint_path="/blocks/rate-limit-manual",
        rate_limit=2,
        rate_limit_window=60,
    )
    return {"blocked": refusal is not None}


@blocks.post("/patterns")
@guard.require_ip(whitelist=["127.0.0.1"])
async def custom_pattern(
    action: str = Body(...), pattern_reversed: str = Body(...)
) -> dict[str, bool]:
    # The pattern arrives reversed: sent as is, the scanner would flag the request
    # that registers it.
    pattern = pattern_reversed[::-1]
    manager = sus_patterns_manager_for(security_config)
    if action == "add":
        return {"changed": await manager.add_pattern(pattern, custom=True)}
    return {"changed": await manager.remove_pattern(pattern, custom=True)}
