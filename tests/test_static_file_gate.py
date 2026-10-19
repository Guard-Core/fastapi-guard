from pathlib import Path

import pytest
from fastapi import FastAPI
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.staticfiles import StaticFiles

from guard import SecurityConfig
from guard.asgi import PureASGISecurityMiddleware
from guard.middleware import SecurityMiddleware


def _tree(root: Path) -> Path:
    for name in (
        "hls/live/segment_001.ts",
        "static/js/app.4f3a.js.map",
        "static/app.py",
        "static/dump.sql",
        "static/app.php",
        "static/real.ts",
        "secret.ts",
    ):
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x")
    (root / "static" / "folder.ts").mkdir()
    return root


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        exclude_paths=[],
        enable_rate_limiting=False,
        ban_on_hostile_signals=False,
    )


def _static_app(root: Path, middleware: type[object]) -> FastAPI:
    app = FastAPI()
    app.mount("/hls", StaticFiles(directory=root / "hls"), name="hls")
    app.mount("/static", StaticFiles(directory=root / "static"), name="static")
    app.add_middleware(middleware, config=_config())
    return app


async def _status(app: FastAPI, path: str) -> int:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        return (await client.get(path)).status_code


@pytest.mark.parametrize("middleware", [SecurityMiddleware, PureASGISecurityMiddleware])
@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("/hls/live/segment_001.ts", 200),
        ("/static/js/app.4f3a.js.map", 200),
        ("/static/real.ts", 200),
        ("/static/real.ts;jsessionid=1", 400),
        ("/hls/live/missing.ts", 400),
        ("/static/js/missing.js.map", 400),
        ("/static/folder.ts", 400),
        ("/static/app.py", 400),
        ("/static/dump.sql", 400),
        ("/static/app.php", 400),
        ("/static/js/app.4f3a.js.map/", 200),
        ("/hls/../static/real.ts", 200),
        ("/nowhere/live/segment_001.ts", 400),
    ],
)
async def test_a_ts_or_map_file_is_clean_only_when_the_static_mount_has_it(
    tmp_path: Path, middleware: type[object], path: str, status: int
) -> None:
    app = _static_app(_tree(tmp_path), middleware)

    assert await _status(app, path) == status


async def test_a_catch_all_route_is_not_a_static_mount(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    app = FastAPI()

    @app.get("/{name:path}")
    async def anything(name: str) -> dict[str, str]:
        return {"name": name}

    app.add_middleware(SecurityMiddleware, config=_config())
    app.mount("/unused", StaticFiles(directory=root / "hls"))

    assert await _status(app, "/hls/live/segment_001.ts") == 400


async def test_a_mounted_app_that_is_not_static_files_is_not_a_static_mount(
    tmp_path: Path,
) -> None:
    app = FastAPI()
    app.mount("/sub", FastAPI())
    app.add_middleware(SecurityMiddleware, config=_config())

    assert await _status(app, "/sub/seg.ts") == 400


async def test_a_traversal_out_of_the_mount_directory_is_not_served(
    tmp_path: Path,
) -> None:
    app = _static_app(_tree(tmp_path), SecurityMiddleware)
    guard = SecurityMiddleware(app, config=_config())
    guard._routing_app = app

    assert await guard.static_file_exists("/static/real.ts") is True
    assert await guard.static_file_exists("/static/../secret.ts") is False
    assert await guard.static_file_exists("/static/..%2fsecret.ts") is False
    assert await guard.static_file_exists("/static/a\x00.ts") is False
    assert await guard.static_file_exists("/static//etc/passwd.ts") is False


async def test_a_mount_inside_a_mount_is_found_with_its_own_prefix(
    tmp_path: Path,
) -> None:
    root = _tree(tmp_path)
    inner = Starlette(routes=[Mount("/files", app=StaticFiles(directory=root / "hls"))])
    app = FastAPI()
    app.mount("/v1", inner)
    guard = SecurityMiddleware(app, config=_config())
    guard._routing_app = app

    assert await guard.static_file_exists("/v1/files/live/segment_001.ts") is True
    assert await guard.static_file_exists("/files/live/segment_001.ts") is False
    assert await guard.static_file_exists("/v1/files/live/other.ts") is False


async def test_the_answer_follows_the_disk_with_no_cache(tmp_path: Path) -> None:
    app = _static_app(_tree(tmp_path), SecurityMiddleware)
    guard = SecurityMiddleware(app, config=_config())
    guard._routing_app = app
    target = tmp_path / "static" / "late.ts"

    assert await guard.static_file_exists("/static/late.ts") is False
    target.write_text("x")
    assert await guard.static_file_exists("/static/late.ts") is True
    target.unlink()
    assert await guard.static_file_exists("/static/late.ts") is False


STATIC_MOUNT_CORPUS = (
    "hls/live/segment_000.ts",
    "hls/live/segment_001.ts",
    "hls/vod/720p/chunk-00042.ts",
    "hls/vod/1080p/chunk-00001.ts",
    "hls/audio/seg-12.ts",
    "assets/index-4f3a9c1e.js.map",
    "assets/vendor-b82d.js.map",
    "assets/main.css.map",
    "_next/static/chunks/app/page-9d8c.js.map",
    "_next/static/chunks/webpack-1a2b.js.map",
    "static/js/main.4f3a.chunk.js.map",
    "static/css/main.8e1.chunk.css.map",
    "dist/bundle.min.js.map",
    "build/static/js/2.abc123.chunk.js.map",
    "js/jquery.min.map",
    "assets/ts/sample.ts",
    "examples/demo.ts",
)


def _corpus_tree(root: Path) -> Path:
    for name in STATIC_MOUNT_CORPUS:
        target = root / "media" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x")
    return root


@pytest.mark.parametrize("middleware", [SecurityMiddleware, PureASGISecurityMiddleware])
@pytest.mark.parametrize("name", STATIC_MOUNT_CORPUS)
async def test_the_static_mount_benign_corpus_is_clean_when_the_files_exist(
    tmp_path: Path, middleware: type[object], name: str
) -> None:
    root = _corpus_tree(tmp_path)
    app = FastAPI()
    app.mount("/media", StaticFiles(directory=root / "media"))
    app.add_middleware(middleware, config=_config())

    assert await _status(app, f"/media/{name}") == 200


@pytest.mark.parametrize("name", STATIC_MOUNT_CORPUS)
async def test_the_static_mount_benign_corpus_is_flagged_without_a_static_mount(
    tmp_path: Path, name: str
) -> None:
    app = FastAPI()

    @app.get("/{name:path}")
    async def anything(name: str) -> dict[str, str]:
        return {"name": name}

    app.add_middleware(SecurityMiddleware, config=_config())

    assert await _status(app, f"/media/{name}") == 400
