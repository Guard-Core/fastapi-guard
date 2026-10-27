import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.models import ErrorResponse, RootResponse
from app.routes import (
    access_router,
    admin_router,
    advanced_router,
    auth_router,
    basic_router,
    behavior_router,
    blocks_router,
    content_router,
    headers_router,
    health_router,
    rate_router,
    surfaces_router,
    test_router,
)
from app.security import build_pure_asgi_config, guard, security_config
from guard import (
    PureASGISecurityMiddleware,
    SecurityMiddleware,
    guard_websocket,
)
from guard.lifespan import make_lifespan
from guard.status import add_status_route

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, Any]:
    logger.info("FastAPI Guard Advanced Example starting up...")
    logger.info("Security features enabled:")
    logger.info(f"  - Rate limiting: {security_config.enable_rate_limiting}")
    logger.info(f"  - IP banning: {security_config.enable_ip_banning}")
    logger.info(
        f"  - Penetration detection: {security_config.enable_penetration_detection}"
    )
    logger.info(f"  - Redis: {security_config.enable_redis}")
    logger.info(f"  - Agent: {security_config.enable_agent}")
    yield
    logger.info("FastAPI Guard Advanced Example shutting down...")


app = FastAPI(
    title="FastAPI Guard Advanced Example",
    description="Production-ready deployment with nginx, gunicorn, and modular layout",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=make_lifespan(lifespan),
)

app.add_middleware(SecurityMiddleware, config=security_config)
app.state.guard_decorator = guard

app.include_router(health_router)
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
app.include_router(surfaces_router)
app.include_router(blocks_router)
add_status_route(app)
app.mount(
    "/assets",
    StaticFiles(directory=Path(__file__).parent / "assets"),
    name="assets",
)

pure_app = FastAPI(title="Pure ASGI guarded sub-app")


@pure_app.api_route("/ping", methods=["GET", "POST"])
async def pure_ping() -> dict[str, bool]:
    return {"pure": True}


app.mount(
    "/pure", PureASGISecurityMiddleware(pure_app, config=build_pure_asgi_config())
)


@app.get(
    "/",
    response_model=RootResponse,
    status_code=200,
    summary="API Root",
    description=(
        "Returns API metadata including version, infrastructure details, and available"
        "route groups."
    ),
)
async def root() -> dict[str, Any]:
    return {
        "message": "FastAPI Guard Advanced Example API",
        "version": "1.0.0",
        "infrastructure": {
            "reverse_proxy": "nginx",
            "process_manager": "gunicorn",
            "cache": "redis",
        },
        "documentation": "/docs",
        "routes": {
            "/health": "Health checks",
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
        },
    }


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


@app.websocket("/ws")
async def websocket_echo(
    websocket: WebSocket, _: None = Depends(guard_websocket)
) -> None:
    await websocket.accept()
    message = await websocket.receive_text()
    await websocket.send_text(message)
    await websocket.close()
