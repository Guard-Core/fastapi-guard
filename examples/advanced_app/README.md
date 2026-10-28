# FastAPI Guard Advanced Example

Production-ready deployment demonstrating fastapi-guard with nginx reverse proxy, gunicorn process management, and modular project layout.

## Architecture

```text
Client -> nginx (port 80) -> gunicorn/uvicorn (port 8000) -> FastAPI + guard middleware
                                                                             |
                                                                        Redis (cache)
```

- **nginx**: Reverse proxy with rate limiting, IP forwarding headers, and connection management
- **gunicorn**: Process manager with uvicorn workers for async support
- **fastapi-guard**: Application-level security middleware (IP filtering, penetration detection, behavioral analysis)
- **Redis**: Distributed cache for rate limiting and IP ban state

## Quick Start

```bash
cd examples/advanced_app
export IPINFO_TOKEN=<your token>  # required: free at https://ipinfo.io/signup
docker compose up --build
```

## Testing

```bash
# Health check (through nginx)
curl http://localhost/health

# Client IP (verify proxy forwarding)
curl http://localhost/basic/ip

# Echo request with headers
curl http://localhost/basic/echo -X POST -H "Content-Type: application/json" -d '{"test": true}'

# XSS detection test
curl http://localhost/test/xss-test -X POST -H "Content-Type: application/json" -d '"<script>alert(1)</script>"'

# Rate limiting test (strict: 1 request per 10 seconds)
for i in $(seq 1 5); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost/rate/strict-limit; done

# API documentation
open http://localhost/docs
```

## Key Differences from simple_app

| Feature | simple_app | advanced_app |
|---------|-----------|--------------|
| Reverse proxy | None | nginx with rate limiting |
| Process manager | uvicorn (dev) | gunicorn + uvicorn workers |
| Docker build | pip install | Multi-stage with uv |
| Runtime user | root | Non-root (guard) |
| Project layout | Single file | Modular routes + security config |
| Health checks | None | Docker health checks on all services |
| Resource limits | None | CPU and memory limits |
| Proxy trust | N/A | trusted_proxy_depth=1 |

## Configuration

Environment variables (see `.env`):

- `REDIS_URL` - Redis connection string
- `REDIS_PREFIX` - Key prefix for Redis
- `IPINFO_TOKEN` - IPInfo API token (required: the country routes need a GeoIP source; the example stops at startup without it, and `docker compose` refuses to start)
- `WEB_CONCURRENCY` - Number of gunicorn workers
- `LOG_LEVEL` - Logging level

## Endpoints

All endpoints from simple_app are available, organized into route modules:

- `/health`, `/ready` - Health checks
- `/basic/*` - Connection test, IP info, echo
- `/access/*` - IP whitelist/blacklist, country, cloud provider filtering
- `/auth/*` - HTTPS, bearer, API key, custom headers
- `/rate/*` - Custom rate limits, geo-based rate limits
- `/behavior/*` - Usage/return monitoring, frequency detection
- `/headers/*` - CSP test, frame test, HSTS info
- `/content/*` - Bot blocking, JSON only, size limit, referrer check
- `/advanced/*` - Time windows, honeypot, suspicious pattern detection
- `/admin/*` - Ban/unban, stats, emergency mode
- `/test/*` - XSS, SQL injection, path traversal, command injection

## Watching the security pipeline shrink

`lifespan=make_lifespan(lifespan)` in `app/main.py` runs `SecurityMiddleware.initialize()` at ASGI startup instead of on the first request, and `app.state.guard_decorator = guard` is set before that runs, so the middleware can see every decorated route. Watch the console (or `docker compose logs fastapi-guard-example`) right after startup for a line from the `guard_core` logger:

```text
Security pipeline initialized with 16 checks: ['route_config', 'https_enforcement', 'request_logging', 'request_size_content', 'required_headers', 'authentication', 'referrer', 'custom_validators', 'time_window', 'cloud_ip_refresh', 'ip_security', 'cloud_provider', 'user_agent', 'rate_limit', 'suspicious_activity', 'custom_request'] (1 skipped)
```

That is the real output captured from this app on `guard-core` 3.10.0+: 16 of the 17 built-in checks were built into the pipeline (`emergency_mode` was skipped because this config sets neither `emergency_mode` nor `enable_dynamic_rules`). The skip count depends on your config and which routes carry decorators.

## Cleanup

```bash
docker compose down -v
```
