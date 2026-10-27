import ast
import re
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_PACKAGE = _ROOT / "guard"
_BASELINE = Path(__file__).with_name("any_ratchet_baseline.txt")
_OVERRIDES = re.compile(
    r"\[\[tool\.mypy\.overrides\]\]\s*module = \[(?P<modules>[^\]]*)\]\s*"
    r"disallow_any_explicit = false",
)
_MODULE_NAME = re.compile(r'^\s*"([^"]+)"', re.MULTILINE)


def _listed_modules() -> list[str]:
    text = (_ROOT / "pyproject.toml").read_text()
    return [
        name
        for block in _OVERRIDES.finditer(text)
        for name in _MODULE_NAME.findall(block["modules"])
    ]


def _module_name(path: Path) -> str:
    parts = list(path.relative_to(_ROOT).with_suffix("").parts)
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _names_any(path: Path) -> bool:
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Name) and node.id == "Any":
            return True
        if isinstance(node, ast.Attribute) and node.attr == "Any":
            return True
        if isinstance(node, ast.ImportFrom) and any(
            alias.name == "Any" for alias in node.names
        ):
            return True
    return False


def test_override_list_equals_the_committed_baseline() -> None:
    listed = _listed_modules()
    baseline = _BASELINE.read_text().split()
    assert len(listed) == len(set(listed)), "a module is listed twice"
    grown = sorted(set(listed) - set(baseline))
    left = sorted(set(baseline) - set(listed))
    assert not grown, (
        "D-189 ratchet: modules added to the disallow_any_explicit = false list "
        f"(clean them instead): {grown}"
    )
    assert not left, (
        "D-189 ratchet: modules left the override list; remove them from "
        f"tests/any_ratchet_baseline.txt too: {left}"
    )


def test_every_unlisted_module_names_no_any() -> None:
    listed = set(_listed_modules())
    regained = [
        _module_name(path)
        for path in sorted(_PACKAGE.rglob("*.py"))
        if _module_name(path) not in listed and _names_any(path)
    ]
    assert not regained, f"clean modules that regained Any: {regained}"


_EXPLICIT_ANY_ERROR = re.compile(r"^(guard/[^:]+\.py):\d+: error: .*\[explicit-any\]")


def test_every_listed_module_still_needs_its_override(tmp_path: Path) -> None:
    # Runs mypy over guard with the override blocks removed, so the strict
    # setting applies to every module: a listed module with no explicit-any error
    # is clean already and has to leave the list.
    strict_config = tmp_path / "mypy_strict.toml"
    strict_config.write_text(_OVERRIDES.sub("", (_ROOT / "pyproject.toml").read_text()))
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "guard",
            "--config-file",
            str(strict_config),
            "--cache-dir",
            str(tmp_path / "cache"),
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    flagged = {
        _module_name(_ROOT / match[1])
        for line in run.stdout.splitlines()
        if (match := _EXPLICIT_ANY_ERROR.match(line))
    }
    stale = sorted(set(_listed_modules()) - flagged)
    assert not stale, (
        "D-189 ratchet: these modules no longer need their override (mypy passes "
        f"for them with disallow_any_explicit on); remove them from the list: {stale}"
    )
