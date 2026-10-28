import importlib
import sys
import warnings

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

from tests.conftest import ADVANCED_APP_DIR

_ROUTED = ("GET", "POST", "PUT", "PATCH", "DELETE")


@pytest.fixture
def surfaces_router(monkeypatch: pytest.MonkeyPatch) -> APIRouter:
    monkeypatch.syspath_prepend(str(ADVANCED_APP_DIR))
    for name in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        monkeypatch.delitem(sys.modules, name)
    router: APIRouter = importlib.import_module("app.routes.surfaces").router
    return router


def test_every_routed_method_answers_and_a_405_lists_them_all(
    surfaces_router: APIRouter,
) -> None:
    app = FastAPI()
    app.include_router(surfaces_router)
    client = TestClient(app)

    for method in _ROUTED:
        response = client.request(method, "/methods/resource")
        assert response.status_code == 200
        assert response.json() == {"method": method}

    refused = client.request("HEAD", "/methods/resource")
    assert refused.status_code == 405
    allowed = {m.strip() for m in refused.headers["allow"].split(",")}
    assert allowed == set(_ROUTED)


def test_each_routed_method_has_its_own_operation_id(
    surfaces_router: APIRouter,
) -> None:
    app = FastAPI()
    app.include_router(surfaces_router)

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        operations = app.openapi()["paths"]["/methods/resource"]

    assert sorted(operations) == sorted(m.lower() for m in _ROUTED)
    operation_ids = [operation["operationId"] for operation in operations.values()]
    assert len(set(operation_ids)) == len(_ROUTED)
