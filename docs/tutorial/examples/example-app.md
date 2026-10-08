---

title: Example Application - FastAPI Guard Demo
description: Learn how to use FastAPI Guard with a complete example application
keywords: fastapi-guard example, example application, security middleware demo, docker compose
---

Example Application
===================

The repository ships two runnable example apps under [`examples/`](https://github.com/Guard-Core/fastapi-guard/tree/master/examples): `simple_app`, a single-file app that exercises every security feature, and `advanced_app`, a production-shaped deployment (nginx, gunicorn, modular routers) built on the same configuration. Both wire `fastapi-guard` correctly, including eager initialization via `make_lifespan`, so their startup logs show the real `guard-core` pipeline output.

___

Features Demonstrated
---------------------

Both apps demonstrate:

- IP whitelist/blacklist filtering (global and per-route)
- Rate limiting (global, per-endpoint, and geographic)
- Penetration detection and prevention
- Auto-banning of suspicious IPs
- Geolocation and cloud-provider filtering
- User agent and referrer filtering
- Behavioral analysis (usage/return monitoring, frequency detection)
- Security headers, CORS, and CSP reporting
- Redis integration

___

simple_app
----------

[`examples/simple_app/main.py`](https://github.com/Guard-Core/fastapi-guard/blob/master/examples/simple_app/main.py) is a single file that configures `SecurityConfig`, wires `SecurityMiddleware`, wires the readiness route (`guard.status.add_status_route`), and defines every route group behind a `SecurityDecorator`:

```python
from guard import SecurityConfig, SecurityDecorator, SecurityMiddleware
from guard.lifespan import make_lifespan
from guard.status import add_status_route

security_config = SecurityConfig(
    whitelist=["127.0.0.1", "::1", "10.0.0.0/8"],
    blacklist=["192.168.100.0/24"],
    enable_rate_limiting=True,
    rate_limit=30,
    rate_limit_window=60,
    enable_ip_banning=True,
    auto_ban_threshold=5,
    enable_penetration_detection=True,
    enable_redis=True,
    redis_url="redis://localhost:6379",
)

app = FastAPI(lifespan=make_lifespan(app_lifespan))
app.add_middleware(SecurityMiddleware, config=security_config)
add_status_route(app)

guard_decorator = SecurityDecorator(security_config)
app.state.guard_decorator = guard_decorator
```

Run it directly:

```bash
cd examples/simple_app
docker compose up
```

Or from the repository root, using the Makefile targets that build the root `compose.yml` service (same app, plus Redis):

```bash
make start-example   # build + run, tears down after
make run-example      # build + run, leaves output attached
```

Route groups (simple_app)
--------------------------

- **`/`**: API info and route map
- **`/basic/*`**: Root, client IP info, health check, echo
- **`/access/*`**: IP whitelist/blacklist, country blocking, cloud provider blocking, bypass demo
- **`/auth/*`**: HTTPS enforcement, bearer auth, API key auth, required custom headers
- **`/rate/*`**: Custom and strict rate limits, geo-based rate limiting
- **`/behavior/*`**: Usage monitoring, return pattern monitoring, frequency detection
- **`/headers/*`**: Security headers overview, CSP test page, CSP report receiver, frame test, HSTS info
- **`/content/*`**: Bot blocking, JSON-only filter, request size limit, referrer check, custom validation
- **`/advanced/*`**: Business-hours access, honeypot detection, suspicious pattern detection
- **`/admin/*`**: Unban IP, stats, clear cache, emergency mode (localhost-only)
- **`/test/*`**: XSS, SQL injection, path traversal, command injection, mixed attack test payloads
- **`/ws`**: WebSocket echo endpoint
- **`/docs`**: Swagger UI for interactive testing

___

advanced_app
------------

[`examples/advanced_app/`](https://github.com/Guard-Core/fastapi-guard/tree/master/examples/advanced_app) is the same security surface split into modular routers behind nginx and gunicorn, meant to model a production layout. See its own [README](https://github.com/Guard-Core/fastapi-guard/blob/master/examples/advanced_app/README.md) for the full architecture diagram and endpoint list.

```bash
cd examples/advanced_app
docker compose up --build
```

___

Testing Security Features
--------------------------

```bash
# Rate limiting (simple_app: 30 requests per 60s by default)
for i in $(seq 1 35); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/basic/; done

# XSS detection
curl -X POST http://localhost:8000/test/xss-test \
  -H "Content-Type: application/json" \
  -d '"<script>alert(1)</script>"'

# SQL injection detection
curl -X POST "http://localhost:8000/test/sql-injection?query=SELECT%20*%20FROM%20users"

# Path traversal detection
curl "http://localhost:8000/test/path-traversal/..%2F..%2F..%2Fetc%2Fpasswd"

# Command injection detection
curl -X POST http://localhost:8000/test/command-injection \
  -H "Content-Type: application/json" \
  -d '";ls;pwd;"'
```

___

Environment Variables
---------------------

Both apps support:

- `IPINFO_TOKEN`: Your IPInfo API token (default: `test_token`)
- `REDIS_URL`: Redis connection URL (default: `redis://redis:6379` inside Compose)
- `REDIS_PREFIX`: Prefix for Redis keys (default: `fastapi_guard:`)

`advanced_app` additionally reads `WEB_CONCURRENCY` (gunicorn worker count) and `LOG_LEVEL`.

___

Watching the Pipeline Shrink
-----------------------------

Both examples wire `make_lifespan`, so `guard-core`'s `guard_core` logger prints a summary line at startup showing exactly which checks were built and how many were skipped for that config, see [First Steps: Eager initialization](../first-steps.md#eager-initialization-with-fastapi-lifespan) and each example's own README for the real captured line.

___

Passive Mode Example
---------------------

For production deployments where you want to assess potential false positives before fully enabling penetration detection, use passive mode:

```python
from fastapi import FastAPI
from guard import IPInfoManager, SecurityConfig, SecurityMiddleware

app = FastAPI(title="My API with Security")

config = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_ipinfo_token_here"),
    # Rate limiting
    rate_limit=100,  # Allow 100 requests
    rate_limit_window=60,  # per minute
    # IP filtering
    whitelist=["127.0.0.1", "192.168.1.0/24"],  # Office network
    # Geolocation
    blocked_countries=["XX", "YY"],  # Block specific countries
    # Logging configuration
    log_request_level="INFO",  # Log normal requests as INFO (for development)
    # log_request_level=None,       # Or disable for production
    log_suspicious_level="WARNING",  # Keep suspicious activity at WARNING level
    # Penetration detection with passive mode
    enable_penetration_detection=True,
    passive_mode=True,  # Don't block, just log
    # Auto-banning (will only be logged in passive mode)
    enable_ip_banning=True,
    auto_ban_threshold=5,  # Number of suspicious requests before ban
    auto_ban_duration=3600,  # Ban duration in seconds (1 hour)
    # Redis for distributed deployment (optional)
    enable_redis=True,
    redis_url="redis://localhost:6379",
)

app.add_middleware(SecurityMiddleware, config=config)


@app.get("/")
def read_root():
    return {"Hello": "World"}
```

You can use any configuration with this mode, but it restricts penetration detection to passive mode. After running in this mode for some time and analyzing logs, switch to full protection by removing `passive_mode=True` or setting it to `False` (the default).
