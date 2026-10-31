# Rate Limiting

## Global

```python
from guard import SecurityConfig

config = SecurityConfig(
    enable_rate_limiting=True,
    rate_limit=100,
    rate_limit_window=60,
)
```

`rate_limit` is the maximum requests per client per `rate_limit_window` (seconds). Defaults: 120 requests per 60 seconds.

## Per-endpoint overrides

`endpoint_rate_limits` maps a route path to `(max_requests, window_seconds)`:

```python
config = SecurityConfig(
    enable_rate_limiting=True,
    rate_limit=100,
    rate_limit_window=60,
    endpoint_rate_limits={
        "/api/login": (5, 60),
        "/api/signup": (3, 60),
    },
)
```

## Decorator form

Use `SecurityDecorator` for per-route limits declared on the endpoint itself. The decorator writes a per-route `RouteConfig` that the middleware picks up at request time:

```python
from fastapi import FastAPI
from guard import SecurityConfig, SecurityDecorator, SecurityMiddleware

config = SecurityConfig(enable_rate_limiting=True)
guard = SecurityDecorator(config)

app = FastAPI()
app.add_middleware(SecurityMiddleware, config=config)


@app.post("/api/login")
@guard.rate_limit(requests=5, window=60)
async def login():
    return {"ok": True}
```

## Redis

With Redis on (`enable_redis=True`, or a Redis connection field such as `redis_url` set; off otherwise since guard-core 5.0.0), counters live in Redis so limits are shared across workers. Without Redis, limits are per-process and a multi-worker deployment effectively multiplies the configured limit by the worker count. Prefer Redis in production.

## When to use which

* Global `rate_limit` / `rate_limit_window`: baseline for the whole app.
* `endpoint_rate_limits`: cheap path-keyed overrides without touching route code.
* `@guard.rate_limit`: when the limit belongs to the route definition (colocated with the handler, version-controlled with the route).
