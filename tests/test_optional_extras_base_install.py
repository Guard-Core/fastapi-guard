import json
import subprocess
import sys
import textwrap
from typing import Any

import pytest

from tests.redis_isolation import REDIS_URL, suite_redis_prefix

PACKAGE = "guard"
DISTRIBUTION = "fastapi-guard"
FOUR = ("redis", "maxminddb", "aiohttp", "requests")
DOWNLOADER_MISSING = ("aiohttp",)
OTHER_DOWNLOADER_MISSING = ("requests",)


def _run_without(blocked: tuple[str, ...], body: str) -> Any:
    script = (
        "import json, sys, warnings\n"
        "warnings.simplefilter('ignore')\n"
        f"for name in {blocked!r}:\n"
        "    sys.modules[name] = None\n" + textwrap.dedent(body)
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def _serve(blocked: tuple[str, ...], config_kwargs: str) -> Any:
    return _run_without(blocked, SERVE.replace("CONFIG_KWARGS", config_kwargs))


SERVE = """
import guard
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard import SecurityConfig, SecurityMiddleware
app = FastAPI()
app.add_middleware(SecurityMiddleware, config=SecurityConfig(CONFIG_KWARGS))
@app.get("/")
def root():
    return {"ok": True}
with TestClient(app, client=("127.0.0.1", 5000)) as client:
    status = client.get("/").status_code
names = ("redis", "maxminddb", "aiohttp", "requests")
loaded = [m for m in names if sys.modules.get(m)]
print(json.dumps([status, loaded]))
"""


def test_the_adapter_imports_and_serves_with_none_of_the_four_installed() -> None:
    status, loaded = _serve(FOUR, "")
    assert status == 200
    assert loaded == []


def test_a_redis_config_with_an_agent_serves_without_aiohttp_or_requests() -> None:
    config_kwargs = (
        f"redis_url={REDIS_URL!r}, redis_prefix={suite_redis_prefix('wp49pin')!r}, "
        "enable_agent=True, "
        "agent_api_key='wp49-pin-agent-key', agent_endpoint='http://127.0.0.1:9'"
    )
    status, loaded = _serve(("maxminddb", "aiohttp", "requests"), config_kwargs)
    assert status == 200
    assert "aiohttp" not in loaded
    assert "requests" not in loaded


def test_each_extra_feature_is_refused_naming_guard_cores_and_the_adapters_extra() -> (
    None
):
    refused = _run_without(
        FOUR,
        f"""
        import {PACKAGE}
        from {PACKAGE} import SecurityConfig
        config = SecurityConfig(enable_redis=False)
        cases = {{
            "redis": ("redis", dict(enable_redis=True, redis_url="redis://x")),
            "cloud": ("cloud", dict(block_cloud_providers={{"AWS"}})),
            "geo": ("geo", dict(ipinfo_token="t", blocked_countries={{"US"}})),
        }}
        out = {{}}
        for label, (extra, kwargs) in cases.items():
            seen = {{}}
            for path in ("construction", "assignment", "copy"):
                try:
                    if path == "construction":
                        SecurityConfig(**kwargs)
                    elif path == "assignment":
                        for key, value in kwargs.items():
                            setattr(config, key, value)
                    else:
                        config.model_copy(update=kwargs)
                except ValueError as error:
                    text = str(error)
                    seen[path] = (
                        "guard-core[" + extra + "]" in text
                        and "{DISTRIBUTION}[" + extra + "]" in text
                    )
            out[label] = seen
        print(json.dumps(out))
        """,
    )
    for label in ("redis", "cloud", "geo"):
        assert refused[label] == {
            "construction": True,
            "assignment": True,
            "copy": True,
        }, label


def _refused_at_app_build(blocked: tuple[str, ...], config_kwargs: str) -> str:
    early = "from guard_core import SecurityConfig as EarlyConfig\n"
    early += "early_config = EarlyConfig(" + config_kwargs + ")\n"
    script = (
        "import json, sys, warnings\n"
        "warnings.simplefilter('ignore')\n"
        f"for name in {blocked!r}:\n"
        "    sys.modules[name] = None\n"
        + early
        + textwrap.dedent(
            SERVE.replace("SecurityConfig(CONFIG_KWARGS)", "early_config")
        )
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=False
    )
    assert result.returncode != 0
    assert "200" not in result.stdout
    return result.stderr


CLOUD_KWARGS = "block_cloud_providers={'AWS'}"
GEO_KWARGS = "ipinfo_token='t', blocked_countries={'US'}"


def test_a_config_built_before_the_adapter_import_is_still_refused_for_cloud() -> None:
    stderr = _refused_at_app_build(DOWNLOADER_MISSING, CLOUD_KWARGS)
    assert "DownloaderNotInstalledError" in stderr
    assert f"{DISTRIBUTION}[cloud]" in stderr


def test_a_config_built_before_the_adapter_import_is_still_refused_for_geo() -> None:
    stderr = _refused_at_app_build(DOWNLOADER_MISSING, GEO_KWARGS)
    assert "DownloaderNotInstalledError" in stderr
    assert f"{DISTRIBUTION}[geo]" in stderr


def test_the_other_trees_downloader_is_not_needed() -> None:
    status, _ = _serve(OTHER_DOWNLOADER_MISSING, "block_cloud_providers={'AWS'}")
    assert status == 200


def test_the_lazy_reexports_resolve_to_the_engine_objects() -> None:
    import guard

    for name in (
        "RedisManager",
        "redis_handler",
        "CloudManager",
        "cloud_handler",
        "IPInfoManager",
        "RateLimitManager",
        "rate_limit_handler",
    ):
        assert getattr(guard, name) is not None
    missing = "not_an_export"
    with pytest.raises(AttributeError, match=missing):
        getattr(guard, missing)
