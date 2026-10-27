from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.staticfiles import StaticFiles

from guard import SecurityConfig
from guard.lifespan import guard_lifespan, make_lifespan
from guard.middleware import SecurityMiddleware

Lifespan = Callable[[FastAPI], AbstractAsyncContextManager[None]]


def _app(root: Path, lifespan: Lifespan | None) -> FastAPI:
    (root / "module.ts").write_text("x")
    app = FastAPI(lifespan=lifespan)
    app.mount("/assets", StaticFiles(directory=root), name="assets")
    app.add_middleware(
        SecurityMiddleware,
        config=SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=True,
            exclude_paths=[],
            enable_rate_limiting=False,
            ban_on_hostile_signals=False,
        ),
    )
    return app


def _statuses(app: FastAPI) -> tuple[int, int]:
    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        return (
            client.get("/assets/module.ts").status_code,
            client.get("/assets/missing.ts").status_code,
        )


def test_a_served_ts_file_is_clean_without_the_lifespan(tmp_path: Path) -> None:
    assert _statuses(_app(tmp_path, None)) == (200, 400)


@pytest.mark.parametrize("lifespan", [guard_lifespan, make_lifespan()])
def test_a_served_ts_file_is_clean_under_the_lifespan(
    tmp_path: Path, lifespan: Lifespan
) -> None:
    assert _statuses(_app(tmp_path, lifespan)) == (200, 400)
