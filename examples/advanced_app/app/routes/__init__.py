from app.routes.access_control import router as access_router
from app.routes.admin import router as admin_router
from app.routes.advanced import router as advanced_router
from app.routes.auth import router as auth_router
from app.routes.basic import router as basic_router
from app.routes.behavioral import router as behavior_router
from app.routes.content import router as content_router
from app.routes.headers import router as headers_router
from app.routes.health import router as health_router
from app.routes.rate_limiting import router as rate_router
from app.routes.surfaces import blocks as blocks_router, router as surfaces_router
from app.routes.testing import router as test_router

__all__ = [
    "access_router",
    "admin_router",
    "advanced_router",
    "auth_router",
    "basic_router",
    "blocks_router",
    "behavior_router",
    "content_router",
    "headers_router",
    "health_router",
    "rate_router",
    "surfaces_router",
    "test_router",
]
