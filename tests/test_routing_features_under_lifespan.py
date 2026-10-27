import logging
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

import pytest
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from guard import SecurityConfig, SecurityDecorator
from guard.lifespan import guard_lifespan, make_lifespan
from guard.middleware import SecurityMiddleware
from guard.status import add_status_route
from guard.websocket import guard_websocket

Lifespan = Callable[[FastAPI], AbstractAsyncContextManager[None]]

LIFESPANS = [
    pytest.param(None, id="no-lifespan"),
    pytest.param(guard_lifespan, id="guard_lifespan"),
    pytest.param(make_lifespan(), id="make_lifespan"),
]


def _config(
    *,
    exclude_paths: list[str] | None = None,
    enable_rate_limiting: bool = False,
    endpoint_rate_limits: dict[str, tuple[int, int]] | None = None,
    route_resolution_strict: bool = False,
) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_rate_limiting=enable_rate_limiting,
        enable_ip_banning=False,
        ban_on_hostile_signals=False,
        enable_penetration_detection=True,
        exclude_paths=exclude_paths or [],
        endpoint_rate_limits=endpoint_rate_limits or {},
        route_resolution_strict=route_resolution_strict,
    )


def _client(app: FastAPI) -> TestClient:
    return TestClient(app, client=("127.0.0.1", 12345))


@pytest.mark.parametrize("lifespan", LIFESPANS)
def test_a_route_decorator_config_applies(lifespan: Lifespan | None) -> None:
    config = _config(enable_rate_limiting=True)
    decorator = SecurityDecorator(config)
    app = FastAPI(lifespan=lifespan)
    app.state.guard_decorator = decorator
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/limited")
    @decorator.rate_limit(requests=1, window=60)
    async def limited() -> dict[str, bool]:
        return {"ok": True}

    with _client(app) as client:
        statuses = [client.get("/limited").status_code for _ in range(3)]

    assert statuses == [200, 429, 429]


@pytest.mark.parametrize("lifespan", LIFESPANS)
def test_an_excluded_path_skips_detection_and_the_rest_does_not(
    lifespan: Lifespan | None,
) -> None:
    app = FastAPI(lifespan=lifespan)
    app.add_middleware(SecurityMiddleware, config=_config(exclude_paths=["/open"]))

    @app.get("/open")
    async def open_route() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/closed")
    async def closed_route() -> dict[str, bool]:
        return {"ok": True}

    attack = {"q": "<script>alert(1)</script>"}
    with _client(app) as client:
        assert client.get("/open", params=attack).status_code == 200
        assert client.get("/closed", params=attack).status_code == 400


def _typo_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if "matches no registered route" in r.getMessage()
    ]


@pytest.mark.parametrize("lifespan", LIFESPANS)
def test_the_route_prefix_lookup_finds_the_apps_routes(
    lifespan: Lifespan | None, caplog: pytest.LogCaptureFixture
) -> None:
    app = FastAPI(lifespan=lifespan)
    app.add_middleware(
        SecurityMiddleware,
        config=_config(
            exclude_paths=["/real/page", "/typo/page"],
            endpoint_rate_limits={"/real/page": (5, 60)},
        ),
    )

    @app.get("/real/page")
    async def page() -> dict[str, bool]:
        return {"ok": True}

    with caplog.at_level(logging.WARNING), _client(app) as client:
        assert client.get("/real/page").status_code == 200

    warned = _typo_warnings(caplog)
    assert any("/typo/page" in w for w in warned)
    assert not any("/real/page" in w for w in warned)


@pytest.mark.parametrize("lifespan", LIFESPANS)
def test_a_wrong_method_is_a_405_with_allow(lifespan: Lifespan | None) -> None:
    app = FastAPI(lifespan=lifespan)
    app.add_middleware(SecurityMiddleware, config=_config(route_resolution_strict=True))

    @app.get("/items")
    async def items() -> dict[str, bool]:
        return {"ok": True}

    with _client(app) as client:
        response = client.post("/items")

    assert (response.status_code, response.headers.get("allow")) == (405, "GET")


@pytest.mark.parametrize("lifespan", LIFESPANS)
def test_the_status_route_answers(lifespan: Lifespan | None) -> None:
    app = FastAPI(lifespan=lifespan)
    app.add_middleware(SecurityMiddleware, config=_config())
    add_status_route(app)

    with _client(app) as client:
        response = client.get("/_guard/status")

    assert response.status_code == 200
    assert "cloud_providers" in response.json()


@pytest.mark.parametrize("lifespan", LIFESPANS)
def test_the_websocket_guard_refuses_an_attack_and_accepts_a_clean_handshake(
    lifespan: Lifespan | None,
) -> None:
    app = FastAPI(lifespan=lifespan)
    app.add_middleware(SecurityMiddleware, config=_config())

    @app.websocket("/ws")
    async def socket(websocket: WebSocket, _: None = Depends(guard_websocket)) -> None:
        await websocket.accept()
        await websocket.send_text("connected")
        await websocket.close()

    with _client(app) as client:
        with client.websocket_connect("/ws") as ok:
            assert ok.receive_text() == "connected"
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws?q=<script>alert(1)</script>"):
                pass
