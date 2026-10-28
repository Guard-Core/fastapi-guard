FastAPI Guard Example App
==========================

This example demonstrates how to use FastAPI Guard as middleware in your FastAPI application.

___

Playground
----------

You can try FastAPI Guard without installation at the interactive demo site:

**[https://playground.guard-core.com](https://playground.guard-core.com)**

___

Running the example
-------------------

Using Docker Compose
-------------

```bash
export IPINFO_TOKEN=<your token>  # required: free at https://ipinfo.io/signup
# Start the example app and Redis
docker compose up

# Restart
docker compose restart

# Stop
docker compose down
```

___

Available endpoints
-------------------

- `/` - API info and route map
- `/basic/*` - Root, client IP info, health check, echo
- `/access/*` - IP whitelist/blacklist, country blocking, cloud provider blocking, bypass demo
- `/auth/*` - HTTPS enforcement, bearer auth, API key auth, required custom headers
- `/rate/*` - Custom and strict rate limits, geo-based rate limiting
- `/behavior/*` - Usage monitoring, return pattern monitoring, frequency detection, combined rules
- `/headers/*` - Security headers overview, CSP test page, CSP report receiver, frame test, HSTS info
- `/content/*` - Bot blocking, JSON-only filter, request size limit, referrer check, custom validation
- `/advanced/*` - Business-hours access, honeypot detection, suspicious pattern detection
- `/admin/*` - Unban IP, stats, clear cache, emergency mode, cloud provider status (localhost-only)
- `/test/*` - XSS, SQL injection, path traversal, command injection, and mixed attack test payloads
- `/ws` - WebSocket echo endpoint

___

Environment variables
---------------------

- `IPINFO_TOKEN` - Token for IPInfo geolocation (required: the country routes need a GeoIP source; the example stops at startup without it, and `docker compose` refuses to start)
- `REDIS_URL` - URL for Redis connection (default: `redis://localhost:6379`)
- `REDIS_PREFIX` - Prefix for Redis keys (default: `fastapi_guard:`)

___

Configuration
-------------

See the configuration in `main.py` for an example of how to set up the middleware with various security options.

___

Watching the security pipeline shrink
--------------------------------------

`app.state.guard_decorator` is wired before the middleware initializes, and `lifespan=make_lifespan(app_lifespan)` runs that initialization at ASGI startup instead of on the first request. Watch the console (or `docker compose logs`) right after startup for a line from the `guard_core` logger:

```text
Security pipeline initialized with 16 checks: ['route_config', 'https_enforcement', 'request_logging', 'request_size_content', 'required_headers', 'authentication', 'referrer', 'custom_validators', 'time_window', 'cloud_ip_refresh', 'ip_security', 'cloud_provider', 'user_agent', 'rate_limit', 'suspicious_activity', 'custom_request'] (1 skipped)
```

That is the real output captured from this app on `guard-core` 3.10.0+: 16 of the 17 built-in checks were built into the pipeline (`emergency_mode` was skipped because this config sets neither `emergency_mode` nor `enable_dynamic_rules`). The skip count changes with your config and with which routes carry decorators; it is guard-core reporting exactly what it built, not a fixed number.
