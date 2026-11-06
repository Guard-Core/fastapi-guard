from pathlib import Path

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def test_guard_core_requirement_is_5_0_0_up_to_6() -> None:
    lines = [
        line.strip()
        for line in _PYPROJECT.read_text().splitlines()
        if line.strip().startswith('"guard-core>')
    ]
    assert lines
    assert set(lines) == {'"guard-core>=5.0.0,<6",'}
