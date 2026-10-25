import importlib
import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest
from fastapi.testclient import TestClient

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
BLOCKED_COUNTRY_IP = "1.2.3.4"
ALLOWED_COUNTRY_IP = "9.9.9.9"
EXAMPLE_NAMES = ("simple_app", "advanced_app")


class _CountryStubGeoIPHandler:
    @property
    def is_initialized(self) -> bool:
        return True

    async def initialize(self) -> None:
        return

    async def initialize_redis(self, redis_handler: object) -> None:
        return

    async def initialize_agent(self, agent_handler: object) -> None:
        return

    def get_country(self, ip: str) -> str | None:
        return "CN" if ip == BLOCKED_COUNTRY_IP else "US"

    async def refresh(self) -> None:
        return

    def close(self) -> None:
        return


def _load_example(name: str, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.setenv("IPINFO_TOKEN", "test_token")
    monkeypatch.setenv(
        "REDIS_URL", os.environ.get("REDIS_URL", "redis://localhost:6379")
    )
    if name == "simple_app":
        spec = importlib.util.spec_from_file_location(
            "simple_app_main", EXAMPLES / name / "main.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    monkeypatch.syspath_prepend(str(EXAMPLES / name))
    for loaded in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        monkeypatch.delitem(sys.modules, loaded)
    return importlib.import_module("app.main")


def _example_client(module: ModuleType, client_ip: str) -> TestClient:
    config = module.security_config
    config.geo_ip_handler = _CountryStubGeoIPHandler()
    config.enable_redis = False
    config.enable_ip_banning = False
    config.rate_limit = 100000
    return TestClient(
        module.app, raise_server_exceptions=False, client=(client_ip, 5000)
    )


@pytest.mark.parametrize("name", EXAMPLE_NAMES)
def test_every_documented_example_route_answers_without_a_server_error(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_example(name, monkeypatch)
    with _example_client(module, ALLOWED_COUNTRY_IP) as client:
        paths = module.app.openapi()["paths"]
        answers = {
            (method.upper(), path): client.request(method, path).status_code
            for path, operations in paths.items()
            if "{" not in path
            for method in operations
        }
    assert answers
    assert {key: code for key, code in answers.items() if code >= 500} == {}


@pytest.mark.parametrize("name", EXAMPLE_NAMES)
def test_example_country_block_route_blocks_the_blocked_country_only(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_example(name, monkeypatch)
    with _example_client(module, BLOCKED_COUNTRY_IP) as client:
        blocked = client.get("/access/country-block").status_code
    with _example_client(module, ALLOWED_COUNTRY_IP) as client:
        allowed = client.get("/access/country-block").status_code
    assert (blocked, allowed) == (403, 200)
