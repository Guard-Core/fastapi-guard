from collections.abc import Sequence

from fastapi import FastAPI, params
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse

from guard.lifespan import _declared_security_entry, _find_security_middleware

_NO_MIDDLEWARE = (
    "add_status_route() must be called after "
    "app.add_middleware(SecurityMiddleware, config=...)"
)


def add_status_route(
    app: Starlette,
    path: str = "/_guard/status",
    dependencies: Sequence[params.Depends] | None = None,
) -> None:
    if _declared_security_entry(app) is None:
        raise RuntimeError(_NO_MIDDLEWARE)

    async def guard_initialization_status(request: Request) -> JSONResponse:
        # Resolved per request: the registered middleware is not built until the
        # app starts, and the status must be the built one's.
        middleware = _find_security_middleware(app)
        if middleware is None:
            raise RuntimeError(_NO_MIDDLEWARE)
        return JSONResponse(middleware.get_initialization_status())

    if isinstance(app, FastAPI):
        app.add_api_route(
            path,
            guard_initialization_status,
            methods=["GET"],
            include_in_schema=False,
            dependencies=dependencies,
        )
        return

    if dependencies:
        raise TypeError(
            f"dependencies require a FastAPI app; add_status_route received {type(app)}"
        )

    app.add_route(
        path, guard_initialization_status, methods=["GET"], include_in_schema=False
    )
