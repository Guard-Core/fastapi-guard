import importlib.util
import os
from pathlib import Path

import pytest

EXAMPLE_MAIN = (
    Path(__file__).resolve().parents[1] / "examples" / "simple_app" / "main.py"
)


def test_example_app_still_starts_with_lifespan_and_status_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "REDIS_URL", os.environ.get("REDIS_URL", "redis://localhost:6379")
    )
    monkeypatch.setenv("IPINFO_TOKEN", os.environ.get("IPINFO_TOKEN") or "test_token")

    spec = importlib.util.spec_from_file_location("simple_app_main", EXAMPLE_MAIN)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.app is not None
    assert any(getattr(r, "path", None) == "/_guard/status" for r in module.app.routes)
