<p align="center">
    <a href="https://guard-core.github.io/fastapi-guard/latest/">
        <img src="https://raw.githubusercontent.com/Guard-Core/fastapi-guard/master/docs/assets/fastapi_guard_legend.svg" alt="FastAPI Guard">
    </a>
</p>

<p align="center">
  <a href="https://badge.fury.io/py/fastapi-guard"><img src="https://badge.fury.io/py/fastapi-guard.svg?cache=none" alt="PyPI version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://github.com/Guard-Core/fastapi-guard/actions/workflows/ci.yml"><img src="https://github.com/Guard-Core/fastapi-guard/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Guard-Core/fastapi-guard/actions/workflows/release.yml"><img src="https://github.com/Guard-Core/fastapi-guard/actions/workflows/release.yml/badge.svg" alt="Release"></a>
  <a href="https://github.com/Guard-Core/fastapi-guard/actions/workflows/code-ql.yml"><img src="https://github.com/Guard-Core/fastapi-guard/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://guard-core.github.io/fastapi-guard/latest/"><img src="https://img.shields.io/badge/Docs-latest-blue.svg" alt="Docs"></a>
  <a href="https://pepy.tech/project/fastapi-guard"><img src="https://pepy.tech/badge/fastapi-guard" alt="Downloads"></a>
</p>

<p align="center">
  <a href="https://guard-core.com">Website</a> &middot;
  <a href="https://guard-core.github.io/fastapi-guard/latest/">Docs</a> &middot;
  <a href="https://playground.guard-core.com">Playground</a> &middot;
  <a href="https://app.guard-core.com">Dashboard</a> &middot;
  <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

<p align="center">
    <a href="https://peerpush.com/p/guard-core" target="_blank" rel="noopener" style="width: 230px;"><img src="https://peerpush.com/p/guard-core/badge.png" alt="Guard Core badge" style="width: 230px;" /></a>
</p>

<p align="center">
  Production-ready security middleware for FastAPI.<br>
  IP filtering, rate limiting, signature-based attack-pattern detection, and 20+ per-route security decorators.
</p>

---

<table align="center">
<tr>
<td align="center" width="50%">

### 📋 Using this in production?

**[Tell me what is working and what is not →](https://forms.gle/ZpjkQgT7KGWgRoQP7)**

Six minutes. It decides what gets built next.<br>
Anonymous unless you choose otherwise.

</td>
<td align="center" width="50%">

### 📊 State of FastAPI Security 2026

**[Take the survey →](https://forms.gle/7npRKzN8BZLfZj326)**

Five minutes, nothing to sign up for.<br>
Results published publicly, free for everyone.

</td>
</tr>
</table>

---

## Quick Start

```bash
uv add fastapi-guard        # uv (recommended)
pip install fastapi-guard    # pip
poetry add fastapi-guard     # poetry
```

---

## Example

```python
from fastapi import FastAPI
from guard import SecurityMiddleware, SecurityConfig

app = FastAPI()

config = SecurityConfig(
    enable_rate_limiting=True,
    rate_limit=100,
    rate_limit_window=60,
    enable_ip_banning=True,
    auto_ban_threshold=5,
    auto_ban_duration=86400,
    custom_log_file="security.log",
    enforce_https=True,
    enable_cors=True,
    cors_allow_origins=["*"],
    cors_allow_methods=["GET", "POST"],
    cors_allow_headers=["*"],
    cors_allow_credentials=True,
    cors_expose_headers=["X-Custom-Header"],
    cors_max_age=600,
    block_cloud_providers={"AWS", "GCP", "Azure"},
)

app.add_middleware(SecurityMiddleware, config=config)
```

For production, wire `guard.lifespan.guard_lifespan` into `FastAPI(lifespan=...)` so initialization runs at app startup instead of on the first request, see [Eager initialization](https://guard-core.github.io/fastapi-guard/latest/tutorial/first-steps/#eager-initialization-with-fastapi-lifespan).

A connection with no client address (a Unix domain socket, some serverless ASGI adapters) is rejected with 403 by default (`fail_secure=True`); set `fail_secure=False` to run the pipeline with identity `"unknown"` instead, allowed unless a whitelist or a country allow-list is configured (blacklist, country, and cloud checks cannot match without an address; detection and the shared rate-limit bucket still apply). Add the literal string `"unix"` to `trusted_proxies` to resolve the real client from `X-Forwarded-For` on such a connection, see [Proxy Security](https://guard-core.github.io/fastapi-guard/latest/tutorial/security/proxy-security/#unix-sockets-and-serverless-adapters).

`SecurityMiddleware` protects HTTP requests only; it never runs for WebSocket connections. Secure a `@app.websocket` route explicitly with `Depends(guard_websocket)`, see [WebSockets](https://guard-core.github.io/fastapi-guard/latest/tutorial/websockets/).

---

## Per-Route Security Decorators

Apply security rules at the endpoint level with composable decorators:

```python
from guard import SecurityConfig, SecurityDecorator

config = SecurityConfig(
    auth_verifier=lambda request, credential: {"user": "demo"} if credential else None,
)
guard = SecurityDecorator(config)


@app.get("/api/payments")
@guard.require_auth(type="bearer")
@guard.rate_limit(requests=10, window=60)
@guard.block_countries(["CN", "RU"])
@guard.require_https()
async def process_payment():
    return {"status": "ok"}
```

`require_auth` and `api_key_auth` require a verifier (per-route `verifier=` or global `SecurityConfig.auth_verifier`); without one the request is rejected with 401. For a presence-only `Authorization` header gate, use `require_authorization_header(scheme="bearer")` instead. See [the authentication tutorial](https://guard-core.github.io/fastapi-guard/latest/tutorial/decorators/authentication/) for the full migration.

**Available decorator categories:**

- **Access** --- `require_ip`, `block_countries`, `allow_countries`, `block_clouds`, `bypass`
- **Auth** --- `require_https`, `require_auth`, `api_key_auth`, `require_headers`
- **Rate Limiting** --- `rate_limit`, `geo_rate_limit`
- **Content** --- `block_user_agents`, `content_type_filter`, `max_request_size`, `require_referrer`, `custom_validation`, `detection_exclusion`
- **Behavioral** --- `usage_monitor`, `return_monitor`, `suspicious_frequency`, `behavior_analysis`
- **Advanced** --- `time_window`, `honeypot_detection`, `suspicious_detection`

[Full decorator reference](https://guard-core.github.io/fastapi-guard/latest/api/decorators/)

---

## Cloud Dashboard

FastAPI Guard has a centralized cloud platform for real-time monitoring and threat analysis across all your applications.

- **[Dashboard](https://app.guard-core.com)** --- real-time security events, threat intelligence, attack pattern analytics
- **[Playground](https://playground.guard-core.com)** --- try every security feature in-browser with real attack data from a live server
- **Dynamic Rules** --- update security configuration from the dashboard without redeploying
- **GDPR Tools** --- consent management, data export, account deletion

Connect your existing setup in 2 minutes:

```bash
uv add guard-agent    # or: pip install guard-agent
```

```python
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware

security_config = SecurityConfig(
    enable_agent=True,
    agent_api_key="your-api-key",
    agent_endpoint="https://api.guard-core.com",
    agent_project_id="your-project-id",
    agent_buffer_size=100,
    agent_flush_interval=2,
    agent_enable_events=True,
    agent_enable_metrics=True,
    enable_dynamic_rules=True,
    dynamic_rule_interval=60,
)

app = FastAPI()
app.add_middleware(SecurityMiddleware, config=security_config)
```

That is the entire integration. The middleware drives the agent's lifecycle for you --- **do not** import `guard_agent`, construct an `AgentConfig`, or wire a `lifespan` hook when using fastapi-guard; doing so spins up a second agent that never sees traffic.

Free tier includes 10,000 events/month --- no credit card required.

> The core library is fully self-contained and MIT licensed. The cloud dashboard is optional.

### Monitoring agent buffer health

When `enable_agent=True`, the middleware exposes an `agent_stats` property that returns the current buffer drop counters and transport circuit-breaker state without needing to reach into the agent directly:

```python
middleware: SecurityMiddleware = ...

stats = middleware.agent_stats
# {"enabled": True, "buffer_stats": {"events_dropped": 0, "metrics_dropped": 0, ...},
#  "transport_stats": {"circuit_breaker_state": "CLOSED", ...}, ...}
```

When the agent is disabled or failed to initialize, the property returns `{"enabled": False}`. Read it on each scrape; it reflects live counters and is not cached.

---

## Ecosystem

FastAPI Guard is built on [guard-core](https://github.com/Guard-Core/guard-core), a framework-agnostic security engine. The same protection is available across Python, TypeScript, and Rust.

### Python

| Package | Role | PyPI |
|---|---|---|
| [guard-core](https://github.com/Guard-Core/guard-core) | Framework-agnostic security engine | [![PyPI](https://img.shields.io/pypi/v/guard-core)](https://pypi.org/project/guard-core/) |
| [guard-agent](https://github.com/Guard-Core/guard-agent) | Telemetry agent | [![PyPI](https://img.shields.io/pypi/v/guard-agent)](https://pypi.org/project/guard-agent/) |
| [fastapi-guard](https://github.com/Guard-Core/fastapi-guard) | FastAPI / Starlette adapter (this package) | [![PyPI](https://img.shields.io/pypi/v/fastapi-guard)](https://pypi.org/project/fastapi-guard/) |
| [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard) | Flask adapter | [![PyPI](https://img.shields.io/pypi/v/flaskapi-guard)](https://pypi.org/project/flaskapi-guard/) |
| [djapi-guard](https://github.com/Guard-Core/djapi-guard) | Django adapter | [![PyPI](https://img.shields.io/pypi/v/djapi-guard)](https://pypi.org/project/djapi-guard/) |
| [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard) | Tornado adapter | [![PyPI](https://img.shields.io/pypi/v/tornadoapi-guard)](https://pypi.org/project/tornadoapi-guard/) |

### TypeScript / JavaScript

Published under the [`@guardcore`](https://www.npmjs.com/org/guardcore) npm scope. Source in the [guard-core-ts](https://github.com/Guard-Core/guard-core-ts) monorepo. **Production-ready.**

| Package | Role | npm |
|---|---|---|
| [@guardcore/core](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/core) | Core engine | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fcore)](https://www.npmjs.com/package/@guardcore/core) |
| [@guardcore/express](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/express) | Express adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fexpress)](https://www.npmjs.com/package/@guardcore/express) |
| [@guardcore/nestjs](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/nestjs) | NestJS adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fnestjs)](https://www.npmjs.com/package/@guardcore/nestjs) |
| [@guardcore/fastify](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/fastify) | Fastify adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Ffastify)](https://www.npmjs.com/package/@guardcore/fastify) |
| [@guardcore/hono](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/hono) | Hono adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fhono)](https://www.npmjs.com/package/@guardcore/hono) |

### Rust

Published on crates.io. **🚧 Placeholder crates: implementation in progress.**

| Package | Role | crates.io |
|---|---|---|
| [guard-core](https://github.com/Guard-Core/guard-core-rs) | Core engine | [![crates.io](https://img.shields.io/crates/v/guard-core)](https://crates.io/crates/guard-core) |
| [actix-guard-rs](https://github.com/Guard-Core/actix-guard-rs) | Actix adapter | [![crates.io](https://img.shields.io/crates/v/actix-guard-rs)](https://crates.io/crates/actix-guard-rs) |
| [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs) | Axum adapter | [![crates.io](https://img.shields.io/crates/v/axum-guard-rs)](https://crates.io/crates/axum-guard-rs) |
| [rocket-guard-rs](https://github.com/Guard-Core/rocket-guard-rs) | Rocket adapter | [![crates.io](https://img.shields.io/crates/v/rocket-guard-rs)](https://crates.io/crates/rocket-guard-rs) |
| [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs) | Tower adapter | [![crates.io](https://img.shields.io/crates/v/tower-guard-rs)](https://crates.io/crates/tower-guard-rs) |

### AI Coding Agents

| Package | Role | PyPI |
|---|---|---|
| [guard-core-mcp](https://github.com/Guard-Core/guard-core-mcp) | MCP server: config validation, docs search, detection sandbox | [![PyPI](https://img.shields.io/pypi/v/guard-core-mcp)](https://pypi.org/project/guard-core-mcp/) |

An MCP server that answers questions about FastAPI Guard from the version **installed in your project**, rather than from a model's memory of it. It validates a config against the real `SecurityConfig` model (catching silently-ignored typos like `redis_failopen`), looks up any field's type, default and description, searches the bundled docs, and runs a payload through the real detection engine to show whether it would be blocked and by which pattern.

```bash
uv add --dev guard-core-mcp
claude mcp add guard-core -- uv run guard-core-mcp
```

Install it into the same environment as FastAPI Guard; it introspects what is actually installed there, so an isolated run (`uvx`) has nothing to read.

---

## Documentation

- [Installation](https://guard-core.github.io/fastapi-guard/latest/installation/)
- [First Steps](https://guard-core.github.io/fastapi-guard/latest/tutorial/first-steps/)
- [Configuration Reference](https://guard-core.github.io/fastapi-guard/latest/tutorial/configuration/security-config/)
- [Decorator Reference](https://guard-core.github.io/fastapi-guard/latest/api/decorators/)
- [API Reference](https://guard-core.github.io/fastapi-guard/latest/api/overview/)
- [Example App](https://guard-core.github.io/fastapi-guard/latest/tutorial/examples/example-app/)
- [Redis Integration](https://guard-core.github.io/fastapi-guard/latest/tutorial/redis-integration/caching/)

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

New security features (checks, detection patterns, handlers) should be contributed to [guard-core](https://github.com/Guard-Core/guard-core). This repo covers the FastAPI/Starlette adapter layer.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Author

[Renzo Franceschini](https://github.com/Guard-Core)
