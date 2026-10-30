from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig

from guard import PureASGISecurityMiddleware, SecurityMiddleware


@pytest.mark.parametrize("middleware", [SecurityMiddleware, PureASGISecurityMiddleware])
def test_the_headers_manager_is_given_the_path_without_the_root_path(
    middleware: type[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str | None] = []
    original = SecurityHeadersManager.get_headers

    async def recording(
        self: SecurityHeadersManager,
        request_path: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, str]:
        seen.append(request_path)
        return await original(self, request_path, *args, **kwargs)

    monkeypatch.setattr(SecurityHeadersManager, "get_headers", recording)
    app = FastAPI()
    app.add_middleware(
        middleware,
        config=SecurityConfig(
            enable_redis=False, enable_rate_limiting=False, trusted_proxies=[]
        ),
    )

    @app.get("/thing")
    async def thing() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app, root_path="/app", client=("203.0.113.5", 5000)) as client:
        assert client.get("/app/thing").status_code == 200

    assert seen
    assert set(seen) == {"/thing"}
