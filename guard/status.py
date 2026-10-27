from collections.abc import Sequence

from fastapi import FastAPI, params
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse

from guard.lifespan import _find_security_middleware


def add_status_route(
    app: Starlette,
    path: str = "/_guard/status",
    dependencies: Sequence[params.Depends] | None = None,
) -> None:
    middleware = _find_security_middleware(app)
    if middleware is None:
        raise RuntimeError(
            "add_status_route() must be called after "
            "app.add_middleware(SecurityMiddleware, config=...)"
        )

    async def guard_initialization_status(request: Request) -> JSONResponse:
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
