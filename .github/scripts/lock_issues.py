"""Open or refresh one issue per advisory whose fix cannot be locked (D-157).

The GHSA id in the title is the key. usage: lock_issues.py <decision.json>
[--dry-run]. GH_BIN overrides the gh binary (tests).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

MARKER = "<!-- lock-security: managed by .github/workflows/lock-security.yml -->"


def gh(args: list[str], dry_run: bool, mutating: bool) -> str:
    command = [os.environ.get("GH_BIN", "gh"), *args]
    if dry_run and mutating:
        print("DRY-RUN", " ".join(command))
        return ""
    return subprocess.run(command, capture_output=True, text=True, check=True).stdout


def issue_body(
    ghsa: str, package: str, installed: str, fixes: list[str], reasons: list[str]
) -> str:
    fixed = ", ".join(fixes) if fixes else "none published"
    why = "\n".join(f"- {reason}" for reason in reasons)
    return (
        f"{MARKER}\n\n"
        f"pip-audit reports [{ghsa}](https://github.com/advisories/{ghsa}) "
        f"against `{package}` {installed} in the committed `uv.lock`.\n\n"
        f"First fixed versions: {fixed}.\n\n"
        "The fix cannot be locked inside the allowed range, "
        f"so no lock PR was opened:\n\n{why}\n\n"
        "The hourly run re-checks this advisory and the issue is refreshed here, "
        "not duplicated. A fix that only waits for the 7 day cooldown opens the "
        "lock PR on its own once the cooldown has passed.\n"
    )


def sync(decision: dict[str, Any], dry_run: bool) -> int:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for issue in decision["issues"]:
        entry = grouped.setdefault(
            (issue["ghsa"], issue["package"], issue["installed"]),
            {"fixes": set(), "reasons": []},
        )
        entry["fixes"].update(issue["fix_versions"])
        if issue["reason"] not in entry["reasons"]:
            entry["reasons"].append(issue["reason"])
    for (ghsa, package, installed), entry in sorted(grouped.items()):
        title = f"{ghsa}: {package} {installed} has no fix inside the allowed range"
        body = issue_body(
            ghsa, package, installed, sorted(entry["fixes"]), entry["reasons"]
        )
        found = json.loads(
            gh(
                [
                    "issue",
                    "list",
                    "--state",
                    "open",
                    "--search",
                    f'"{ghsa}" in:title',
                    "--json",
                    "number,title,body",
                ],
                dry_run,
                False,
            )
            or "[]"
        )
        existing = [i for i in found if ghsa in i["title"] and MARKER in i["body"]]
        with tempfile.TemporaryDirectory() as tmp:
            body_file = Path(tmp) / "body.md"
            body_file.write_text(body)
            if not existing:
                gh(
                    [
                        "issue",
                        "create",
                        "--title",
                        title,
                        "--body-file",
                        str(body_file),
                    ],
                    dry_run,
                    True,
                )
            elif (
                existing[0]["body"].strip() != body.strip()
                or existing[0]["title"] != title
            ):
                gh(
                    [
                        "issue",
                        "edit",
                        str(existing[0]["number"]),
                        "--title",
                        title,
                        "--body-file",
                        str(body_file),
                    ],
                    dry_run,
                    True,
                )
            else:
                print(f"unchanged: #{existing[0]['number']} {ghsa}")
    return len(grouped)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decision", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    count = sync(json.loads(args.decision.read_text()), args.dry_run)
    print(f"advisories handled: {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
