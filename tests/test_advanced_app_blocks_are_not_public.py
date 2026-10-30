from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_STATE_CHANGING = [
    ("POST", "/blocks/patterns", {"action": "add", "pattern_reversed": "zzqq"}),
    ("GET", "/blocks/behavior", None),
    ("GET", "/blocks/rate-limit", None),
]


@pytest.mark.parametrize(("method", "path", "body"), _STATE_CHANGING)
def test_an_outside_client_is_refused_on_a_route_that_changes_guard_state(
    advanced_app_main: Any, method: str, path: str, body: dict[str, str] | None
) -> None:
    app: FastAPI = advanced_app_main.app

    with TestClient(app, client=("203.0.113.5", 50000)) as client:
        response = client.request(method, path, json=body)

    assert response.status_code == 403


@pytest.mark.parametrize(("method", "path", "body"), _STATE_CHANGING)
def test_the_local_client_still_reaches_the_route(
    advanced_app_main: Any, method: str, path: str, body: dict[str, str] | None
) -> None:
    app: FastAPI = advanced_app_main.app

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        response = client.request(method, path, json=body)

    assert response.status_code == 200
