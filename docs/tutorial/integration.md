---

title: Integration Guide — fastapi-guard, guard-core, guard-agent
description: How fastapi-guard, guard-core, and guard-agent fit together. Decision tree + three concrete integration paths with full code.
keywords: fastapi-guard integration, guard-core, guard-agent, saas telemetry, encrypted telemetry, security middleware
---

Integration Guide
=================

Three packages, one stack. This page is the canonical reference for which to install and how to wire them together — without the dead-end patterns that the older docs accumulated.

What each package is
---------------------

| Package | Layer | What it does | Always required? |
|---|---|---|---|
| `guard-core` | Engine | Framework-agnostic security checks: IP banning, rate limiting, signature-based attack-pattern detection, geo-IP, cloud-provider blocking, dynamic-rule cache, behavioral counters, security-headers handler, Redis integration. Pure Python, no framework deps. | **Yes** — but pulled in transitively. |
| `fastapi-guard` | Adapter | Wires `guard-core`'s checks into FastAPI via `SecurityMiddleware`. Provides `SecurityDecorator` for per-route declarative policies. | **Yes** if you want FastAPI integration. (Use `flaskapi-guard`, `djapi-guard`, etc. for other frameworks.) |
| `guard-agent` | Telemetry | Buffers security events + metrics in memory and ships them to a SaaS endpoint (`api.guard-core.com` by default). Also fetches dynamic rules from the dashboard. Optional. | **No** — only if you want a hosted dashboard, paid features, or dynamic-rule sync. |

What guard-core is useful for
------------------------------

It catches a specific class of HTTP-layer attacks — the ones an automated, AI-orchestrated attacker runs at scale:

- **Polymorphic payloads** — variation-based SQLi/XSS that defeats signature WAFs (token-overlap scoring catches them)
- **Reconnaissance** — endpoint enumeration, 404 spam, honeypot probing, banner grabbing
- **Distributed attacks** — when paired with behavioral patterns enabled (per-IP rate limits alone are not enough)
- **Known bad actors** — country/cloud/tor blocking, IP reputation
- **Layer-7 abuse** — auto-ban thresholds, custom rate limits per route, CORS enforcement, security headers

It does **not** cover:

- **Prompt injection** against LLM endpoints (HTTP-layer guard, not prompt-layer)
- **Model output exfiltration** / token-budget exhaustion against AI services
- **Application-logic vulnerabilities** (auth bypass, IDOR, business-logic flaws — those are your code's responsibility)
- **Network-layer DDoS** — that's Cloudflare/AWS Shield's job; guard-core sits behind those

Decision tree
-------------

```text
┌─────────────────────────────────────────────────────────┐
│ Do you want a hosted dashboard for security events?     │
└────────────────────┬────────────────────────────────────┘
                     │
            ┌────────┴────────┐
           NO                YES
            │                 │
            ▼                 ▼
    ┌────────────┐    ┌──────────────────────────────────┐
    │  Path A    │    │ Do you handle PII or work in a    │
    │ Standalone │    │ regulated industry where ingress  │
    └────────────┘    │ payload encryption is a contract  │
                      │ requirement?                      │
                      └──────────┬────────────────────────┘
                                 │
                        ┌────────┴────────┐
                       NO                YES
                        │                 │
                        ▼                 ▼
                 ┌────────────┐    ┌────────────┐
                 │  Path B    │    │  Path C    │
                 │  SaaS,     │    │  SaaS,     │
                 │  plain     │    │  encrypted │
                 │  telemetry │    │  telemetry │
                 └────────────┘    └────────────┘
```

___

Path A — Standalone (no SaaS)
-----------------------------

You install `fastapi-guard` only. Everything runs in-process. State lives in Redis (recommended) or memory.

=== "uv"

    ```bash
    uv add fastapi-guard
    ```

=== "poetry"

    ```bash
    poetry add fastapi-guard
    ```

=== "pip"

    ```bash
    pip install fastapi-guard
    ```

```python
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware

config = SecurityConfig(
    enable_redis=True,
    redis_url="redis://localhost:6379",
    rate_limit=100,
    rate_limit_window=60,
    auto_ban_threshold=5,
    auto_ban_duration=300,
    enable_penetration_detection=True,
    enable_ip_banning=True,
    enable_rate_limiting=True,
    blocked_user_agents=["badbot", "scrapy", "nikto"],
)

app = FastAPI()
app.add_middleware(SecurityMiddleware, config=config)
```

That's the whole integration. No `enable_agent`, no `agent_*` fields, no `lifespan` hook, no telemetry shipping.

**When to use this:** internal tools, on-prem deploys with no outbound internet, MVPs that don't need a dashboard yet, or as a baseline before opting in to telemetry.

___

Path B — SaaS dashboard, plain telemetry
----------------------------------------

You add `guard-agent` and configure `agent_*` fields on `SecurityConfig`. The middleware starts and stops the agent's flush loop for you — **do not** manually construct an `AgentConfig` or wire a `lifespan` (older docs showed that pattern; it creates a second singleton that doesn't receive traffic).

=== "uv"

    ```bash
    uv add fastapi-guard guard-agent
    ```

=== "poetry"

    ```bash
    poetry add fastapi-guard guard-agent
    ```

=== "pip"

    ```bash
    pip install fastapi-guard guard-agent
    ```

```python
import os
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware

try:
    from guard import __version__ as _GUARD_VERSION
except ImportError:
    _GUARD_VERSION = None

config = SecurityConfig(
    # Local protection (same as Path A)
    enable_redis=True,
    redis_url="redis://localhost:6379",
    rate_limit=100,
    rate_limit_window=60,
    auto_ban_threshold=5,
    enable_penetration_detection=True,
    # SaaS telemetry
    enable_agent=True,
    agent_api_key=os.environ["GUARD_API_KEY"],
    agent_project_id=os.environ["GUARD_PROJECT_ID"],
    agent_endpoint="https://api.guard-core.com",
    agent_buffer_size=100,
    agent_flush_interval=2,
    agent_enable_events=True,
    agent_enable_metrics=True,
    agent_guard_version=_GUARD_VERSION,  # so SaaS can attribute events to wrapper version
    # Optional — pull dynamic rule updates from the dashboard
    enable_dynamic_rules=True,
    dynamic_rule_interval=60,
)

app = FastAPI()
app.add_middleware(SecurityMiddleware, config=config)
```

**That is the entire integration.** No explicit `AgentConfig`, no `guard_agent()` factory call, no `@asynccontextmanager` lifespan. The middleware drives the agent lifecycle.

Where credentials come from
---------------------------

1. Sign in to [`app.guard-core.com`](https://app.guard-core.com)
2. Create a project — copy the `proj_*` ID into `GUARD_PROJECT_ID`
3. Generate an API key for that project — copy the `fg_*` key into `GUARD_API_KEY`
4. Done. The agent's first flush registers your project in the dashboard.

Wire format
-----------

The agent posts batches to `POST https://api.guard-core.com/api/v1/events` with a JSON body containing your events + metrics. Standard HTTPS. CloudFlare in front of nginx in front of the Guard Core API. No special networking.

___

Path C — SaaS dashboard with encrypted telemetry
-----------------------------------------------

For deployments that handle PII, sensitive customer data, or work in regulated industries (SOC 2, HIPAA, GDPR Art. 32) where end-to-end payload encryption between agent and SaaS is a contract requirement.

Same install as Path B. Configuration adds **two** things:

1. An API key with **encryption enforcement enabled** (issue this in the dashboard — it's a flag on the API key)
2. A per-project AES-256-GCM encryption key (issued at the same time)

```python
import os
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware

try:
    from guard import __version__ as _GUARD_VERSION
except ImportError:
    _GUARD_VERSION = None

config = SecurityConfig(
    enable_redis=True,
    redis_url="redis://localhost:6379",
    enable_agent=True,
    agent_api_key=os.environ["GUARD_API_KEY_W_ENCRYPTION"],  # encryption-enforced key
    agent_project_id=os.environ["GUARD_PROJECT_ID"],
    agent_endpoint="https://api.guard-core.com",
    agent_project_encryption_key=os.environ["GUARD_PROJECT_ENCRYPTION_KEY"],
    agent_buffer_size=100,
    agent_flush_interval=2,
    agent_guard_version=_GUARD_VERSION,
)

app = FastAPI()
app.add_middleware(SecurityMiddleware, config=config)
```

When `agent_project_encryption_key` is set, the agent posts to a different route — `POST /api/v1/events/encrypted` — with the body encrypted client-side via AES-256-GCM. The SaaS decrypts only with the per-project key (which the SaaS stores wrapped under a master KEK), so even an attacker with backup-database access can't read your event payloads without the master key.

Critical: key/api-key pairing
----------------------------

The encryption key is **paired** with a specific API key in the dashboard. Mixing keys produces:

```text
HTTP 400: Failed to decrypt payload: Invalid or tampered payload
```

If you rotate the API key, you must also retrieve and update the encryption key — they are issued together.

___

Configuration reference — agent fields on `SecurityConfig`
--------------------------------------------------------

| Field | Type | Default | Notes |
|---|---|---|---|
| `enable_agent` | `bool` | `False` | Master switch. False → no telemetry, no dynamic rules. |
| `agent_api_key` | `str \| None` | `None` | Required when `enable_agent=True`. |
| `agent_project_id` | `str \| None` | `None` | The `proj_*` ID from the dashboard. Required for dashboard attribution. |
| `agent_endpoint` | `str` | `https://api.guard-core.com` | Override only for self-hosted Guard Core deploys. |
| `agent_buffer_size` | `int` | `100` | In-memory event buffer cap. The SaaS caps request bodies at 256 KiB, and a flush serializes the whole buffer into one POST, so keep this at the default (or lower for verbose events) instead of raising it toward thousands; prefer a shorter `agent_flush_interval` for lower latency. See [the agent integration reference](https://github.com/Guard-Core/fastapi-guard/blob/master/guard/.agents/skills/fastapi-guard/references/agent-integration.md) for the split-or-drop behavior if a batch does 413. |
| `agent_flush_interval` | `int` | `30` | Seconds between automatic buffer flushes. `2` is a reasonable production setting. |
| `agent_enable_events` | `bool` | `True` | Ship security events. |
| `agent_enable_metrics` | `bool` | `True` | Ship request metrics. |
| `agent_timeout` | `int` | `30` | HTTPS timeout for SaaS calls. |
| `agent_retry_attempts` | `int` | `3` | Retry attempts on transient failures. |
| `agent_project_encryption_key` | `str \| None` | `None` | When set, agent uses the encrypted ingestion path (Path C). Pairs with an encryption-enforced API key. |
| `agent_guard_version` | `str \| None` | `None` | Framework wrapper version (typically `guard.__version__`). The SaaS uses this to attribute telemetry to your `fastapi-guard` version. |
| `enable_dynamic_rules` | `bool` | `False` | Pull rule updates from the dashboard at `dynamic_rule_interval`. |
| `dynamic_rule_interval` | `int` | `300` | Seconds between dynamic-rule polls. |

___

Common pitfalls
---------------

"Failed to decrypt payload" on every batch
-------------------------------------------

Cause: encryption key paired with a different API key.
Fix: re-copy the encryption key from the dashboard alongside the API key it was issued with.

Agent doesn't ship events even though `enable_agent=True`
------------------------------------------------------

Cause #1: `agent_api_key` is empty string instead of `None`. The middleware's `to_agent_config()` returns `None` when the key is missing.
Cause #2: You manually constructed an `AgentConfig` and called `guard_agent(agent_config)` from your app's module-level code. This creates a `SyncGuardAgentHandler` (singleton class A) before the middleware creates the `GuardAgentHandler` (singleton class B). Two different singletons; the one the middleware controls is the one telemetry actually flows through.

Fix for both: stop creating `AgentConfig`/`guard_agent()` manually. Configure `agent_*` on `SecurityConfig` only and let the middleware run the agent lifecycle.

`nginx 413 Request Entity Too Large` on `/api/v1/events/encrypted`
-----------------------------------------------------------------

Cause: `agent_buffer_size` was raised well past the default, so a flush now serializes a batch bigger than nginx's default `client_max_body_size` (1m) can pass through. The SaaS itself caps ingestion bodies at 256 KiB regardless, so a batch this large would 413 there too even with a larger nginx limit.
Fix: bring `agent_buffer_size` back toward the default (100, or lower for verbose events) instead of raising nginx's `client_max_body_size`, see the `agent_buffer_size` row above.

`HASH_PEPPER is required to compute peppered hashes`
---------------------------------------------------

Cause: this is a SaaS-side error. The Guard Core SaaS hashes IPs with HMAC-SHA256 using a per-deployment pepper. If the pepper isn't injected into the SaaS container's environment, every event ingestion raises this.
Fix: this is a Guard Core operations issue, not yours — file a ticket if you're using the hosted SaaS. If you're self-hosting, ensure `HASH_PEPPER` is set in your docker-compose env.

Dashboard shows zero events even though the app is running
---------------------------------------------------------

1. Confirm `agent_api_key` and `agent_project_id` are set and non-empty.
2. Check your application logs for `Guard Agent initialized successfully`.
3. Check for `guard_agent.transport` warnings. If you see HTTP errors with class names like `RemoteProtocolError` or `WriteError`, the request is being closed at the TCP level — usually a reverse-proxy `client_max_body_size` issue or a CloudFlare WAF rule firing on the encrypted body shape.
4. Confirm your project hasn't tripped the SaaS-side ingestion circuit breaker — if you've been sending malformed batches, it suspends ingestion for that project for ~30 seconds.

___

What if you outgrow this stack?
------------------------------

`guard-core` exposes the engine as a protocol-based library. If you have a non-FastAPI service (Django, Flask, Tornado, raw ASGI), use the framework's adapter — `djapi-guard`, `flaskapi-guard`, `tornadoapi-guard` — they all consume the same `guard-core` engine and the same `guard-agent`. Telemetry is unified across frameworks in a single dashboard project.
