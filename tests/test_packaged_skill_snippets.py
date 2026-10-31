import re
from pathlib import Path

import pytest

import guard

SKILL_DIR = Path(guard.__file__).parent / ".agents" / "skills"
PYTHON_BLOCK = re.compile(r"^```python\n(.*?)^```", re.DOTALL | re.MULTILINE)
SKILL_FILES = sorted(SKILL_DIR.rglob("*.md"))


def _python_blocks(path: Path) -> list[str]:
    return PYTHON_BLOCK.findall(path.read_text(encoding="utf-8"))


def test_the_packaged_skill_files_are_found() -> None:
    assert SKILL_FILES
    assert all(_python_blocks(path) for path in SKILL_FILES)


@pytest.mark.parametrize(
    "path", SKILL_FILES, ids=lambda path: f"{path.parent.name}/{path.name}"
)
def test_every_python_block_of_a_packaged_skill_file_runs(path: Path) -> None:
    namespace: dict[str, object] = {"__name__": "skill_snippet"}
    for number, block in enumerate(_python_blocks(path), start=1):
        exec(compile(block, f"{path.name} block {number}", "exec"), namespace)
