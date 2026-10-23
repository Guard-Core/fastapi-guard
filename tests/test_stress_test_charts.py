"""The stress test script runs without matplotlib and skips only its charts."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "examples/testing/stress_test.py"


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("stress_test_under_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def results() -> dict[str, list[SimpleNamespace]]:
    category = SimpleNamespace(
        category="xss",
        blocked_count=3,
        passed_count=1,
        avg_response_time_ms=2.5,
        block_rate=75.0,
    )
    return {"categories": [category]}


def charter(module: ModuleType) -> SimpleNamespace:
    generate = next(
        value.generate_charts
        for value in vars(module).values()
        if isinstance(value, type) and hasattr(value, "generate_charts")
    )
    return SimpleNamespace(generate_charts=lambda *args: generate(None, *args))


def test_script_imports_and_skips_charts_when_matplotlib_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(sys.modules, "matplotlib", None)
    monkeypatch.setitem(sys.modules, "matplotlib.pyplot", None)
    module = load_script()
    prefix = str(tmp_path / "run")
    charter(module).generate_charts(results(), prefix)
    assert module.CHARTS_NEED_MATPLOTLIB in capsys.readouterr().out
    assert list(tmp_path.iterdir()) == []


def test_charts_are_drawn_when_matplotlib_is_installed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    matplotlib = pytest.importorskip("matplotlib")
    matplotlib.use("Agg")
    module = load_script()
    prefix = str(tmp_path / "run")
    charter(module).generate_charts(results(), prefix)
    assert (tmp_path / "run_security_analysis.png").is_file()
    assert module.CHARTS_NEED_MATPLOTLIB not in capsys.readouterr().out
