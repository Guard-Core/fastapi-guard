from typing import Any

from fastapi import FastAPI, Request
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from guard import SecurityConfig, SecurityDecorator
from guard.middleware import SecurityMiddleware

_FORWARD_FOR = {"X-Forwarded-For": "203.0.113.5"}


def _approving_verifier(principal: Any) -> Any:
    def verifier(_request: Any, _credential: str) -> Any:
        return principal

    return verifier


def _async_approving_verifier(principal: Any) -> Any:
    async def verifier(_request: Any, _credential: str) -> Any:
        return principal

    return verifier


def _config(security_config: SecurityConfig, **overrides: Any) -> SecurityConfig:
    security_config.trusted_proxies = ("127.0.0.1",)
    security_config.enforce_https = False
    security_config.enable_penetration_detection = False
    for key, value in overrides.items():
        setattr(security_config, key, value)
    return security_config


def _build_app(security_config: SecurityConfig) -> tuple[FastAPI, SecurityDecorator]:
    decorator = SecurityDecorator(security_config)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=security_config)
    app.state.guard_decorator = decorator
    return app, decorator


async def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def test_valid_verifier_token_allows_and_principal_visible_downstream(
    security_config: SecurityConfig,
) -> None:
    principal = {"user": "alice"}
    _config(security_config, auth_verifier=_approving_verifier(principal))
    app, decorator = _build_app(security_config)

    @decorator.require_auth()
    @app.get("/protected")
    async def protected(request: Request) -> dict[str, Any]:
        return {"principal": request.state.auth_principal}

    client = await _client(app)
    try:
        response = await client.get(
            "/protected",
            headers={**_FORWARD_FOR, "Authorization": "Bearer good-token"},
        )
    finally:
        await client.aclose()
    assert response.status_code == 200
    assert response.json()["principal"] == principal


async def test_arbitrary_bearer_rejected_without_verifier(
    security_config: SecurityConfig,
) -> None:
    _config(security_config)
    app, decorator = _build_app(security_config)

    @decorator.require_auth()
    @app.get("/protected")
    async def protected() -> None: ...

    client = await _client(app)
    try:
        response = await client.get(
            "/protected",
            headers={**_FORWARD_FOR, "Authorization": "Bearer attacker-value"},
        )
    finally:
        await client.aclose()
    assert response.status_code == 401
    assert "Authentication required" in response.text


async def test_require_authorization_header_allows_any_bearer_no_principal(
    security_config: SecurityConfig,
) -> None:
    _config(security_config)
    app, decorator = _build_app(security_config)

    @decorator.require_authorization_header(scheme="bearer")
    @app.get("/presence")
    async def presence(request: Request) -> dict[str, Any]:
        has_principal = hasattr(request.state, "auth_principal")
        principal = getattr(request.state, "auth_principal", None)
        return {"ok": True, "has_principal": has_principal, "principal": principal}

    client = await _client(app)
    try:
        response = await client.get(
            "/presence",
            headers={**_FORWARD_FOR, "Authorization": "Bearer anything"},
        )
    finally:
        await client.aclose()
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["principal"] is None
    assert body["has_principal"] is False


async def test_per_route_verifier_overrides_global(
    security_config: SecurityConfig,
) -> None:
    route_principal = {"user": "route"}
    global_principal = {"user": "global"}
    _config(security_config, auth_verifier=_approving_verifier(global_principal))
    app, decorator = _build_app(security_config)

    @decorator.require_auth(verifier=_approving_verifier(route_principal))
    @app.get("/route-verifier")
    async def route_verifier(request: Request) -> dict[str, Any]:
        return {"principal": request.state.auth_principal}

    client = await _client(app)
    try:
        response = await client.get(
            "/route-verifier",
            headers={**_FORWARD_FOR, "Authorization": "Bearer token"},
        )
    finally:
        await client.aclose()
    assert response.status_code == 200
    assert response.json()["principal"] == route_principal


async def test_verifier_denial_rejected(security_config: SecurityConfig) -> None:
    _config(security_config, auth_verifier=_approving_verifier(None))
    app, decorator = _build_app(security_config)

    @decorator.require_auth()
    @app.get("/protected")
    async def protected() -> None: ...

    client = await _client(app)
    try:
        response = await client.get(
            "/protected",
            headers={**_FORWARD_FOR, "Authorization": "Bearer any"},
        )
    finally:
        await client.aclose()
    assert response.status_code == 401
    assert "Authentication required" in response.text


async def test_verifier_raises_fail_closed(security_config: SecurityConfig) -> None:
    def verifier(_request: Any, _credential: str) -> Any:
        raise RuntimeError("jwt decode failed")

    _config(security_config, auth_verifier=verifier)
    app, decorator = _build_app(security_config)
    reached: list[bool] = []

    @decorator.require_auth()
    @app.get("/protected")
    async def protected() -> None:
        reached.append(True)

    client = await _client(app)
    try:
        response = await client.get(
            "/protected",
            headers={**_FORWARD_FOR, "Authorization": "Bearer token"},
        )
    finally:
        await client.aclose()
    assert response.status_code >= 400
    assert reached == []


async def test_async_verifier_awaited(security_config: SecurityConfig) -> None:
    principal = {"user": "carol"}
    _config(security_config, auth_verifier=_async_approving_verifier(principal))
    app, decorator = _build_app(security_config)

    @decorator.require_auth()
    @app.get("/protected")
    async def protected(request: Request) -> dict[str, Any]:
        return {"principal": request.state.auth_principal}

    client = await _client(app)
    try:
        response = await client.get(
            "/protected",
            headers={**_FORWARD_FOR, "Authorization": "Bearer token"},
        )
    finally:
        await client.aclose()
    assert response.status_code == 200
    assert response.json()["principal"] == principal


async def test_api_key_verifier_success(security_config: SecurityConfig) -> None:
    principal = {"user": "dave"}
    _config(security_config, auth_verifier=_approving_verifier(principal))
    app, decorator = _build_app(security_config)

    @decorator.api_key_auth()
    @app.get("/api-key")
    async def api_key(request: Request) -> dict[str, Any]:
        return {"principal": request.state.auth_principal}

    client = await _client(app)
    try:
        response = await client.get(
            "/api-key",
            headers={**_FORWARD_FOR, "X-API-Key": "good"},
        )
    finally:
        await client.aclose()
    assert response.status_code == 200
    assert response.json()["principal"] == principal


async def test_api_key_without_verifier_fail_closed(
    security_config: SecurityConfig,
) -> None:
    _config(security_config)
    app, decorator = _build_app(security_config)

    @decorator.api_key_auth()
    @app.get("/api-key")
    async def api_key() -> None: ...

    client = await _client(app)
    try:
        response = await client.get(
            "/api-key",
            headers={**_FORWARD_FOR, "X-API-Key": "any-value"},
        )
    finally:
        await client.aclose()
    assert response.status_code == 401
    assert "Authentication required" in response.text


async def test_verifier_receives_scheme_stripped_credential(
    security_config: SecurityConfig,
) -> None:
    received: list[str] = []

    def verifier(_request: Any, credential: str) -> Any:
        received.append(credential)
        return {"user": "ok"} if credential == "good-token" else None

    _config(security_config, auth_verifier=verifier)
    app, decorator = _build_app(security_config)

    @decorator.require_auth()
    @app.get("/protected")
    async def protected(request: Request) -> dict[str, Any]:
        return {"principal": request.state.auth_principal}

    client = await _client(app)
    try:
        response = await client.get(
            "/protected",
            headers={**_FORWARD_FOR, "Authorization": "Bearer good-token"},
        )
    finally:
        await client.aclose()
    assert response.status_code == 200
    assert received == ["good-token"]
