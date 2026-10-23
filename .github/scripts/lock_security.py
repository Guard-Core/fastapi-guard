"""Hourly lock security decision (D-157).

Reads the committed uv.lock and never compares with PyPI's latest.
It audits the lock with pip-audit, takes first-party releases inside the
allowed range, moves each vulnerable package to its first fixed version and
reports every advisory whose fix cannot be locked. Only a hit re-locks.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def run(
    cmd: list[str], cwd: Path, check: bool = True
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if check and proc.returncode != 0:
        tail = proc.stderr.strip()[-600:]
        raise RuntimeError(f"{' '.join(cmd)} exit {proc.returncode}: {tail}")
    return proc


def first_party_names(pyproject: Path) -> list[str]:
    text = pyproject.read_text()
    section = re.search(
        r"^\[tool\.uv\.exclude-newer-package\]\n(.*?)(?:\n\[|\Z)", text, re.S | re.M
    )
    if section is None:
        return []
    return re.findall(r'^([A-Za-z0-9_.-]+)\s*=\s*"0 days"', section.group(1), re.M)


def locked_versions(lock: Path) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for name, version in re.findall(
        r'^name = "([^"]+)"\nversion = "([^"]+)"', lock.read_text(), re.M
    ):
        found.setdefault(name, set()).add(version)
    return found


def version_key(version: str) -> tuple[int, ...]:
    # shortcut: pre and post release suffixes are ignored,
    # upgrade to packaging when an advisory needs them
    release = re.match(r"\d+(?:\.\d+)*", version)
    return tuple(int(part) for part in release.group().split(".")) if release else (0,)


def copy_tracked_files(repo: Path, destination: Path) -> None:
    listing = run(["git", "ls-files", "-z"], repo).stdout
    for name in filter(None, listing.split("\0")):
        source = repo / name
        if source.is_file():
            (destination / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination / name)


def requirement_layers(export: str) -> list[list[str]]:
    layers: list[dict[str, str]] = []
    for name, version in sorted(
        set(re.findall(r"^([A-Za-z0-9_.-]+)==([^\s;]+)", export, re.M))
    ):
        for layer in layers:
            if name not in layer:
                layer[name] = version
                break
        else:
            layers.append({name: version})
    return [
        [f"{name}=={version}" for name, version in layer.items()] for layer in layers
    ]


def audit(project: Path, work: Path) -> list[dict[str, Any]]:
    export = run(
        [
            "uv",
            "export",
            "--frozen",
            "--format",
            "requirements-txt",
            "--all-extras",
            "--all-groups",
            "--no-emit-project",
            "--no-hashes",
        ],
        project,
    ).stdout
    found: dict[tuple[str, str, str], dict[str, Any]] = {}
    for index, lines in enumerate(requirement_layers(export)):
        requirements = work / f"requirements-{index}.txt"
        requirements.write_text("\n".join(lines) + "\n")
        proc = run(
            [
                "pip-audit",
                "-r",
                str(requirements),
                "--no-deps",
                "--disable-pip",
                "--format",
                "json",
                "--progress-spinner",
                "off",
            ],
            project,
            check=False,
        )
        if proc.returncode > 1:
            raise RuntimeError(
                f"pip-audit exit {proc.returncode}: {proc.stderr.strip()[-600:]}"
            )
        for dependency in json.loads(proc.stdout)["dependencies"]:
            for vuln in dependency.get("vulns", []):
                ids = [vuln["id"], *vuln.get("aliases", [])]
                ghsa = next((i for i in ids if i.startswith("GHSA-")), vuln["id"])
                entry = found.setdefault(
                    (dependency["name"], dependency["version"], ghsa),
                    {
                        "package": dependency["name"],
                        "installed": dependency["version"],
                        "ghsa": ghsa,
                        "fix_versions": [],
                    },
                )
                entry["fix_versions"] = sorted(
                    {*entry["fix_versions"], *vuln.get("fix_versions", [])},
                    key=version_key,
                )
    return list(found.values())


def first_fixed_version(vulns: list[dict[str, Any]]) -> str | None:
    """First version above the installed one that fixes every advisory, or None."""
    firsts: list[str] = []
    for vuln in vulns:
        above = [
            v
            for v in vuln["fix_versions"]
            if version_key(v) > version_key(vuln["installed"])
        ]
        if not above:
            return None
        firsts.append(min(above, key=version_key))
    return max(firsts, key=version_key)


def decide(repo: Path, lock_out: Path | None) -> dict[str, Any]:
    first_party = first_party_names(repo / "pyproject.toml")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        scratch = work / "scratch"
        scratch.mkdir()
        copy_tracked_files(repo, scratch)
        committed = (repo / "uv.lock").read_text()
        committed_vulns = audit(scratch, work)

        present = [
            name for name in first_party if name in locked_versions(scratch / "uv.lock")
        ]
        if present:
            run(
                ["uv", "lock", *[f"--upgrade-package={name}" for name in present]],
                scratch,
            )
        first_party_changed = (scratch / "uv.lock").read_text() != committed

        issues: list[dict[str, Any]] = []
        fixed: list[dict[str, str]] = []
        remaining = audit(scratch, work) if first_party_changed else committed_vulns
        by_package: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for vuln in remaining:
            by_package.setdefault((vuln["package"], vuln["installed"]), []).append(vuln)
        for (package, installed), vulns in sorted(by_package.items()):
            target = first_fixed_version(vulns)
            reason = f"no published version above {installed} fixes it"
            if target is not None:
                attempt = run(
                    ["uv", "lock", f"--upgrade-package={package}=={target}"],
                    scratch,
                    check=False,
                )
                if attempt.returncode == 0:
                    fixed.append({"package": package, "from": installed, "to": target})
                    continue
                lines = attempt.stderr.strip().splitlines()
                cause = next(
                    (line.strip() for line in lines if "No solution found" in line), ""
                )
                hint = next(
                    (line.strip() for line in lines if "exclude-newer" in line),
                    lines[-1] if lines else "",
                )
                reason = (
                    f"uv could not lock {package}=={target}: {cause} {hint}".strip()[
                        :400
                    ]
                )
            issues.extend({**vuln, "reason": reason} for vuln in vulns)

        run(["uv", "lock", "--check"], scratch)
        final = (scratch / "uv.lock").read_text()
        relock = final != committed
        if lock_out is not None and relock:
            lock_out.write_text(final)
        if fixed:
            unresolved = {(v["ghsa"], v["package"]) for v in issues}
            issues.extend(
                {**v, "reason": "still affected after the re-lock"}
                for v in audit(scratch, work)
                if (v["ghsa"], v["package"]) not in unresolved
            )
    return {
        "action": "+".join(
            a for a, hit in (("pr", relock), ("issue", bool(issues))) if hit
        )
        or "none",
        "relock": relock,
        "first_party_changed": first_party_changed,
        "first_party": first_party,
        "vulnerabilities": committed_vulns,
        "fixed": fixed,
        "issues": issues,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--lock-out", type=Path)
    args = parser.parse_args()
    decision = decide(args.repo.resolve(), args.lock_out)
    args.decision.write_text(json.dumps(decision, indent=2) + "\n")
    print(
        json.dumps(
            {
                k: decision[k]
                for k in ("action", "relock", "first_party_changed", "fixed")
            },
            indent=2,
        )
    )
    print(f"issues: {len(decision['issues'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
