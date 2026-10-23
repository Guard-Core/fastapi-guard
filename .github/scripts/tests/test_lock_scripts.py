"""Offline tests for lock_security.py and lock_issues.py (D-157).

uv and pip-audit are replaced by fixtures that edit and read a scratch uv.lock,
so no network is used and every decision of the hourly job is driven end to end.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


lock_security = load("lock_security")
lock_issues = load("lock_issues")

PYPROJECT = (
    '[tool.uv]\nexclude-newer = "7 days"\n\n'
    '[tool.uv.exclude-newer-package]\nguard-core = "0 days"\n'
)
# advisories by (package, installed version): (GHSA id, first fixed versions)
ADVISORIES = {("idna", "3.6"): ("GHSA-jjg7-2v4v-x38h", ["3.7"])}
# newest version each first-party package has inside the allowed range
FIRST_PARTY_LATEST = {"guard-core": "4.4.0"}


def lock_text(**versions: str) -> str:
    blocks = [
        f'[[package]]\nname = "{n}"\nversion = "{v}"\n' for n, v in versions.items()
    ]
    return "version = 1\n\n" + "\n".join(blocks)


def read_versions(lock: Path) -> dict[str, str]:
    return {
        n: max(v, key=lock_security.version_key)
        for n, v in lock_security.locked_versions(lock).items()
    }


class FakeUv:
    """Edits scratch locks the way `uv lock --upgrade-package` would."""

    def __init__(self) -> None:
        self.unlockable: set[str] = set()
        self.side_effects: dict[str, dict[str, str]] = {}

    def __call__(
        self, cmd: list[str], cwd: Path, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        if cmd[0] != "uv":
            return subprocess.run(
                cmd, cwd=cwd, capture_output=True, text=True, check=check
            )
        lock = cwd / "uv.lock"
        text = lock.read_text()
        for arg in cmd[2:]:
            if not arg.startswith("--upgrade-package="):
                continue
            spec = arg.split("=", 1)[1]
            name, _, version = spec.partition("==")
            if version and name in self.unlockable:
                return subprocess.CompletedProcess(
                    cmd, 1, "", "error: No solution found when resolving"
                )
            version = version or FIRST_PARTY_LATEST.get(name, "")
            old = read_versions(lock)[name]
            text = text.replace(
                f'name = "{name}"\nversion = "{old}"',
                f'name = "{name}"\nversion = "{version}"',
            )
            for other, moved in self.side_effects.get(name, {}).items():
                before = read_versions(lock)[other]
                text = text.replace(
                    f'name = "{other}"\nversion = "{before}"',
                    f'name = "{other}"\nversion = "{moved}"',
                )
        lock.write_text(text)
        return subprocess.CompletedProcess(cmd, 0, "", "")


def fake_audit(project: Path, work: Path) -> list[dict[str, Any]]:
    found = []
    for name, version in read_versions(project / "uv.lock").items():
        if (name, version) in ADVISORIES:
            ghsa, fixes = ADVISORIES[(name, version)]
            found.append(
                {
                    "package": name,
                    "installed": version,
                    "ghsa": ghsa,
                    "fix_versions": fixes,
                }
            )
    return found


@pytest.fixture
def uv(monkeypatch: pytest.MonkeyPatch) -> FakeUv:
    fake = FakeUv()
    monkeypatch.setattr(lock_security, "run", fake)
    monkeypatch.setattr(lock_security, "audit", fake_audit)
    monkeypatch.setattr(lock_security, "upload_time", lambda package, version: None)
    return fake


def make_repo(root: Path, **versions: str) -> Path:
    (root / "pyproject.toml").write_text(PYPROJECT)
    (root / "uv.lock").write_text(lock_text(**versions))
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    return root


def test_vulnerable_pin_opens_a_pr_at_the_first_fixed_version(
    tmp_path: Path, uv: FakeUv
) -> None:
    repo = make_repo(tmp_path, idna="3.6", certifi="2026.7.22")
    out = tmp_path / "uv.lock.new"
    decision = lock_security.decide(repo, out)
    assert decision["action"] == "pr"
    assert decision["fixed"] == [{"package": "idna", "from": "3.6", "to": "3.7"}]
    assert decision["issues"] == []
    assert read_versions(out) == {"idna": "3.7", "certifi": "2026.7.22"}


def test_fix_outside_the_range_opens_an_issue_keyed_by_the_ghsa_id(
    tmp_path: Path, uv: FakeUv
) -> None:
    uv.unlockable.add("idna")
    repo = make_repo(tmp_path, idna="3.6")
    out = tmp_path / "uv.lock.new"
    decision = lock_security.decide(repo, out)
    assert decision["action"] == "issue"
    assert [i["ghsa"] for i in decision["issues"]] == ["GHSA-jjg7-2v4v-x38h"]
    assert "idna==3.7" in decision["issues"][0]["reason"]
    assert not out.exists()


def test_a_fix_inside_the_cooldown_says_when_it_becomes_lockable(
    tmp_path: Path, uv: FakeUv, monkeypatch: pytest.MonkeyPatch
) -> None:
    uv.unlockable.add("idna")
    released = datetime.now(timezone.utc) - timedelta(days=2)
    monkeypatch.setattr(lock_security, "upload_time", lambda package, version: released)
    decision = lock_security.decide(make_repo(tmp_path, idna="3.6"), None)
    assert decision["action"] == "issue"
    assert "inside the 7 day cooldown, lockable from" in decision["issues"][0]["reason"]


def test_a_fix_that_moves_other_packages_down_is_refused(
    tmp_path: Path, uv: FakeUv
) -> None:
    uv.side_effects["idna"] = {"certifi": "2020.1.1"}
    repo = make_repo(tmp_path, idna="3.6", certifi="2026.7.22")
    out = tmp_path / "uv.lock.new"
    decision = lock_security.decide(repo, out)
    assert decision["action"] == "issue"
    assert (
        "would move other packages down: certifi 2026.7.22 to 2020.1.1"
        in decision["issues"][0]["reason"]
    )
    assert not out.exists()


def test_a_clean_lock_needs_no_action(tmp_path: Path, uv: FakeUv) -> None:
    out = tmp_path / "uv.lock.new"
    decision = lock_security.decide(make_repo(tmp_path, idna="3.7"), out)
    assert decision["action"] == "none"
    assert decision["relock"] is False
    assert not out.exists()


def test_a_first_party_release_inside_the_range_is_taken(
    tmp_path: Path, uv: FakeUv
) -> None:
    repo = make_repo(tmp_path, **{"guard-core": "4.3.3", "idna": "3.7"})
    out = tmp_path / "uv.lock.new"
    decision = lock_security.decide(repo, out)
    assert decision["action"] == "pr"
    assert decision["first_party_changed"] is True
    assert decision["first_party"] == ["guard-core"]
    assert read_versions(out)["guard-core"] == "4.4.0"


def test_first_party_names_come_from_the_zero_day_exemptions_only(
    tmp_path: Path,
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[tool.uv.exclude-newer-package]\n"
        'guard-core = "0 days"\n'
        'guard-agent = "0 days"\n'
        'other = "3 days"\n\n'
        "[tool.other]\n"
        'x = "0 days"\n'
    )
    assert lock_security.first_party_names(pyproject) == ["guard-core", "guard-agent"]


def test_the_cooldown_is_read_from_pyproject(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(PYPROJECT)
    assert lock_security.cooldown_days(pyproject) == 7
    pyproject.write_text("[tool.uv]\n")
    assert lock_security.cooldown_days(pyproject) is None


def test_version_key_and_first_fixed_version() -> None:
    assert lock_security.version_key("2.32.4") > lock_security.version_key("2.32.0")
    assert lock_security.version_key("garbage") == (0,)
    two = [
        {"installed": "3.6", "fix_versions": ["3.7"]},
        {"installed": "3.6", "fix_versions": ["3.15", "3.16"]},
    ]
    assert lock_security.first_fixed_version(two) == "3.15"
    assert (
        lock_security.first_fixed_version([{"installed": "1.0", "fix_versions": []}])
        is None
    )
    assert (
        lock_security.first_fixed_version(
            [{"installed": "2.0", "fix_versions": ["1.9"]}]
        )
        is None
    )


def test_requirement_layers_keep_every_forked_version() -> None:
    export = (
        "idna==3.6 ; python_full_version < '3.11'\n"
        "idna==3.7 ; python_full_version >= '3.11'\n"
        "requests==2.32.0\n"
    )
    layers = lock_security.requirement_layers(export)
    assert layers == [["idna==3.6", "requests==2.32.0"], ["idna==3.7"]]


class FakeGh:
    def __init__(self, listing: list[dict[str, Any]]) -> None:
        self.listing = listing
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], dry_run: bool, mutating: bool) -> str:
        if not mutating:
            return json.dumps(self.listing)
        self.calls.append(args)
        return ""


DECISION = {
    "issues": [
        {
            "package": "idna",
            "installed": "3.6",
            "ghsa": "GHSA-jjg7-2v4v-x38h",
            "fix_versions": ["3.7"],
            "reason": "uv could not lock idna==3.7",
        }
    ]
}
TITLE = "GHSA-jjg7-2v4v-x38h: idna 3.6 has no fix inside the allowed range"
BODY = lock_issues.issue_body(
    "GHSA-jjg7-2v4v-x38h", "idna", "3.6", ["3.7"], ["uv could not lock idna==3.7"]
)


def test_issues_are_created_when_none_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGh([])
    monkeypatch.setattr(lock_issues, "gh", fake)
    assert lock_issues.sync(DECISION, dry_run=False) == 1
    assert [c[:4] for c in fake.calls] == [["issue", "create", "--title", TITLE]]


def test_an_identical_issue_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGh([{"number": 7, "title": TITLE, "body": BODY}])
    monkeypatch.setattr(lock_issues, "gh", fake)
    lock_issues.sync(DECISION, dry_run=False)
    assert fake.calls == []


def test_a_changed_issue_is_edited_not_duplicated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeGh([{"number": 7, "title": TITLE, "body": BODY + "stale\n"}])
    monkeypatch.setattr(lock_issues, "gh", fake)
    lock_issues.sync(DECISION, dry_run=False)
    assert [c[:3] for c in fake.calls] == [["issue", "edit", "7"]]


def test_an_unmanaged_issue_with_the_same_id_is_not_touched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeGh([{"number": 9, "title": TITLE, "body": "written by hand"}])
    monkeypatch.setattr(lock_issues, "gh", fake)
    lock_issues.sync(DECISION, dry_run=False)
    assert [c[:2] for c in fake.calls] == [["issue", "create"]]
