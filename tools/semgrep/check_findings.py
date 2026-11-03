"""Compare Semgrep --json output with reviewed.json, fail on anything unreviewed.

LEDGER 6.581, D-252. An entry is keyed by rule id, path and the matched code
text (whitespace collapsed), never by line number: a moved line stays reviewed,
a changed line does not.

Fails on a finding with no entry, an entry with no finding (stale), an entry
whose count differs from the findings, an expired entry, an entry without a
reason, and any Semgrep error. Rule-loading warnings are not findings: only
`results` counts.

Run: uv run --project tools/semgrep --locked python \
tools/semgrep/check_findings.py <semgrep.json> [--today YYYY-MM-DD]
"""

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path

REVIEWED = Path(__file__).with_name("reviewed.json")
SNAPSHOT = Path(__file__).with_name("rules.yaml")
Key = tuple[str, str, str]


@dataclass(frozen=True)
class ReviewedEntry:
    rule: str
    path: str
    code: str
    count: int
    reason: str
    expires: str


def collapse(text: str) -> str:
    return " ".join(text.split())


def matched_text(result: dict) -> str:
    source = Path(result["path"]).read_bytes()
    start, end = result["start"]["offset"], result["end"]["offset"]
    return collapse(source[start:end].decode("utf-8"))


def snapshot_rule_ids() -> set[str]:
    # Standard library only: a rule id is the `id:` key at the top level of a rule.
    text = SNAPSHOT.read_text(encoding="utf-8")
    return set(re.findall(r"^(?:- |  )id: (\S+)\s*$", text, re.MULTILINE))


def canonical_rule_id(check_id: str, rule_ids: set[str]) -> str:
    # Semgrep prefixes each rule id with the directory of the rules file, so
    # the id in the report depends on the working directory.
    matches = [
        rule_id
        for rule_id in rule_ids
        if check_id == rule_id or check_id.endswith(f".{rule_id}")
    ]
    if not matches:
        raise ValueError(f"{check_id!r} is not a rule of {SNAPSHOT.name}")
    return max(matches, key=len)


def finding_keys(report: dict) -> Counter[Key]:
    rule_ids = snapshot_rule_ids()
    return Counter(
        (canonical_rule_id(r["check_id"], rule_ids), r["path"], matched_text(r))
        for r in report["results"]
    )


def load_reviewed() -> list[ReviewedEntry]:
    entries = json.loads(REVIEWED.read_text(encoding="utf-8"))["reviewed"]
    return [ReviewedEntry(**entry) for entry in entries]


def describe(key: Key) -> str:
    return f"{key[0]} {key[1]} {key[2]!r}"


def problems(report: dict, reviewed: list[ReviewedEntry], today: date) -> list[str]:
    found = finding_keys(report)
    out = [f"semgrep error: {e.get('message', e)}" for e in report.get("errors", [])]
    listed: Counter[Key] = Counter()
    for entry in reviewed:
        key = (entry.rule, entry.path, collapse(entry.code))
        listed[key] += entry.count
        if date.fromisoformat(entry.expires) <= today:
            out.append(f"expired {entry.expires}: {describe(key)}")
        if not entry.reason.strip():
            out.append(f"no reason: {describe(key)}")
    for key, count in sorted(found.items()):
        if listed[key] == 0:
            out.append(f"unreviewed: {describe(key)}")
        elif listed[key] != count:
            out.append(f"{count} found, {listed[key]} reviewed: {describe(key)}")
    out.extend(
        f"stale entry, no finding: {describe(k)}"
        for k in sorted(listed)
        if k not in found
    )
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--today", type=date.fromisoformat, default=date.today())
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    out = problems(report, load_reviewed(), args.today)
    for line in out:
        print(line, file=sys.stderr)
    total = sum(finding_keys(report).values())
    print(f"semgrep: {total} findings, {len(out)} problems")
    return 1 if out else 0


if __name__ == "__main__":
    sys.exit(main())
