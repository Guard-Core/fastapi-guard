---

title: Passive to Active - FastAPI Guard
description: A safe, reversible path from log-only monitoring to real blocking, with a way to preview the blast radius before you flip
keywords: passive mode, active mode, enforcement, migration, would-block preview, fastapi guard
---

Passive to Active
=================

FastAPI Guard can run in **passive mode** (detect and log, never block) or **active mode** (detect and block). On a high-traffic, latency- and security-sensitive service the risky moment is the flip: turning enforcement on without accidentally blocking legitimate traffic.

This guide is a safe, reversible path for that flip: **observe → preview → verify → enforce → rollback**. Every step uses signals FastAPI Guard already produces - no new configuration beyond the `passive_mode` flag itself.

The flip is a single boolean. `passive_mode=True` logs only; `passive_mode=False` blocks. Rollback is the same boolean flipped back - no data migration, no redeploy of rules.

___

What passive mode actually does
-------------------------------

`passive_mode` lives on `SecurityConfig` (it is `False` by default - i.e. blocking is the default):

```python
config = SecurityConfig(
    enable_penetration_detection=True,
    passive_mode=True,  # detect + log, never block
)
```

In passive mode, every check still runs and still produces its signal - it just doesn't deny the request. Two artifacts are emitted for every request that *would* have been blocked:

- **A log line prefixed `[PASSIVE MODE]`** (e.g. `[PASSIVE MODE] Penetration attempt detected from ...`). This is what you grep.
- **A telemetry event with `action_taken="logged_only"`** (instead of `"request_blocked"`). If you run the Guard Agent, these events are already shipped off-box to your dashboard, so "what would have been blocked?" is answerable without touching the host.

That means the data you need to size the blast radius of going active **already exists** the moment you turn passive mode on.

___

Step 1 - Observe
----------------

Deploy with passive mode on and let it run long enough to cover a representative slice of traffic (a full business cycle - typically a few days, including any batch/cron peaks):

```python
config = SecurityConfig(
    enable_penetration_detection=True,
    enable_ip_banning=True,
    enable_rate_limiting=True,
    passive_mode=True,
)
```

Nothing is blocked. Everything that *would* be blocked is logged with `[PASSIVE MODE]` and emitted as a `logged_only` telemetry event.

___

Step 2 - Preview the blast radius
---------------------------------

Before flipping, quantify what active mode *would* block. If you run the Guard Agent, the cleanest source is your dashboard: filter events to `action_taken="logged_only"` and group by reason and client IP.

If you only have logs, this read-only recipe summarizes the would-block set straight from a `[PASSIVE MODE]` log file - counts by client IP and a total. It changes nothing; it only reads your log:

```python
import collections
import re
import sys

# Usage: python would_block_preview.py /path/to/security.log
PASSIVE = "[PASSIVE MODE]"
IP_RE = re.compile(r"from\s+(?P<ip>[0-9a-fA-F:.]+)")

by_ip: collections.Counter[str] = collections.Counter()
total = 0
with open(sys.argv[1], encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if PASSIVE not in line:
            continue
        total += 1
        match = IP_RE.search(line)
        by_ip[match.group("ip") if match else "unknown"] += 1

print(f"would-block events: {total}")
print(f"distinct client IPs: {len(by_ip)}")
for ip, count in by_ip.most_common(20):
    print(f"{count:>6}  {ip}")
```

A small, concentrated set (a handful of scanner IPs) is the signal you want before flipping. A large, diffuse set spread across normal client IPs means you have false positives to resolve first (Step 3).

___

Step 3 - Verify false positives
--------------------------------

For each would-block source, decide: real threat, or legitimate traffic caught by a rule?

- **Legitimate IPs** → add them to the `whitelist`. An explicit whitelist match overrides the blacklist (dynamic IP bans still apply), so this is the precise tool for known-good clients and internal callers.
- **Legitimate-but-flagged endpoints** → if a specific route trips penetration detection on expected payloads, scope enforcement with the per-route decorators rather than relaxing it globally (see [Incremental rollout](#incremental-rollout-optional)).
- **Real threats** → leave them to be blocked.

```python
config = SecurityConfig(
    enable_penetration_detection=True,
    passive_mode=True,
    whitelist=["203.0.113.10", "10.0.0.0/8"],  # vetted known-good
)
```

Re-run Step 2 after each adjustment. When the would-block set contains only traffic you are comfortable denying, you are ready to enforce.

___

Step 4 - Enforce
----------------

Flip the single boolean:

```python
config = SecurityConfig(
    enable_penetration_detection=True,
    enable_ip_banning=True,
    enable_rate_limiting=True,
    passive_mode=False,  # now blocking
)
```

The same checks that were logging `[PASSIVE MODE]` now deny requests, and their telemetry switches from `action_taken="logged_only"` to `"request_blocked"`. Nothing else changes - the rules, thresholds and whitelist you vetted in passive mode are exactly what now enforces.

Roll this out the way you would any behavior change: a canary instance first, watching your 4xx rate and the `request_blocked` event stream, before fleet-wide.

___

Step 5 - Rollback
-----------------

If active mode blocks something you did not anticipate, roll back by flipping the same boolean:

```python
config = SecurityConfig(
    passive_mode=True,  # back to log-only, immediately
)
```

Rollback is immediate and total - passive mode resumes logging instead of blocking, with no other state to unwind. Then return to Step 3, resolve the false positive, and re-enforce.

___

Incremental rollout (optional)
------------------------------

`passive_mode` is global. If you would rather enforce in stages than flip everything at once, the per-route decorators let you turn real blocking on for specific routes while the rest of the app stays in passive mode - for example tightening IP access on a sensitive admin route first:

```python
from guard import SecurityDecorator

guard_deco = SecurityDecorator(config)  # config still has passive_mode=True


@app.get("/admin")
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])
async def admin() -> dict[str, str]:
    return {"status": "ok"}
```

There is no per-check "active" flag - enforcement granularity is the global `passive_mode` flip plus the per-route decorators. Stage the routes you are confident about, then flip the global boolean once the remainder is verified.

___

Where the signals live (quick reference)
----------------------------------------

| Signal | What to look for | Source |
|---|---|---|
| Would-block log line | `[PASSIVE MODE]` prefix | your application logs / `custom_log_file` |
| Would-block telemetry | `action_taken="logged_only"` | Guard Agent → dashboard |
| Enforced telemetry | `action_taken="request_blocked"` | Guard Agent → dashboard (after the flip) |

See also [Security Monitoring](monitoring.md) for log configuration and levels.
