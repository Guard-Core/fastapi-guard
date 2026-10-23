---

title: Getting Started with FastAPI Guard
description: First steps guide for implementing FastAPI Guard security features in your FastAPI application
keywords: fastapi security tutorial, fastapi guard setup, python security middleware
---

First Steps
===========

Let's start with a simple example that shows how to add FastAPI Guard to your application.

Create a FastAPI application
----------------------------

First, create a new FastAPI application:

```python
from fastapi import FastAPI
from guard import SecurityMiddleware, SecurityConfig, IPInfoManager

app = FastAPI()
```

___

Configure Security Settings
----------------------------

Create a `SecurityConfig` instance with your desired settings:

```python
config = SecurityConfig(
    geo_ip_handler=IPInfoManager(
        "your_ipinfo_token_here"
    ),  # NOTE: Required for geolocation
    enable_redis=True,  # Enable Redis integration
    redis_url="redis://localhost:6379",  # Redis URL
    rate_limit=100,  # Max requests per minute
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    custom_log_file="security.log",  # Custom log file
)
```

Note: FastAPI Guard only loads resources as needed. The IPInfo database is only downloaded when country filtering is configured, and cloud IP ranges are only fetched when cloud provider blocking is enabled.

___

Add the Middleware
------------------

Add the security middleware to your application:

```python
app.add_middleware(SecurityMiddleware, config=config)
```

___

Complete Example
----------------

Here's a complete example showing basic usage:

```python
from fastapi import FastAPI
from guard import SecurityMiddleware, SecurityConfig, IPInfoManager

app = FastAPI()

config = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_ipinfo_token_here"),
    enable_redis=True,  # Redis enabled
    redis_url="redis://localhost:6379",
    whitelist=["192.168.1.1", "2001:db8::1"],
    blacklist=["10.0.0.1", "2001:db8::2"],
    blocked_countries=["AR", "IT"],
    rate_limit=100,
    custom_log_file="security.log",
)

app.add_middleware(SecurityMiddleware, config=config)


@app.get("/")
async def root():
    return {"message": "Hello World"}
```

___

Run the Application
-------------------

Run your application using uvicorn:

```bash
uvicorn main:app --reload
```

Your API is now protected by FastAPI Guard! 🛡️

___

Eager initialization with FastAPI lifespan
------------------------------------------

!!! warning "`lazy_init=False` alone does not give you boot-time initialization"
    Without lifespan wiring, fastapi-guard initializes lazily on the **first request** - the Redis connection, cloud-IP fetches, pipeline build, and agent / OTEL / Logfire startup all happen there, no matter how `SecurityConfig.lazy_init` is set. `lazy_init` only controls whether that initialization (whenever it happens) awaits cloud-IP/geo-IP warmup inline or backgrounds it - see [`lazy_init`](configuration/security-config.md#redis-settings). Getting initialization to run at ASGI startup instead of on the first request requires wiring one of the three hooks below.

Without any of them, the first caller pays the full initialization cost, and a middleware that then reports itself as uninitialized on that first request is expected, not a bug.

You own the app: `guard_lifespan`
----------------------------------

With `guard_lifespan`, all of that work runs at ASGI startup, and the first request hits a pre-warmed middleware:

```python
from fastapi import FastAPI
from guard.lifespan import guard_lifespan
from guard.middleware import SecurityMiddleware
from guard_core.models import SecurityConfig

config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")

app = FastAPI(lifespan=guard_lifespan)
app.add_middleware(SecurityMiddleware, config=config)
```

You have your own lifespan to compose with: `make_lifespan`
--------------------------------------------------------------

If you already have a custom lifespan, compose them with `make_lifespan`:

```python
from contextlib import asynccontextmanager

from guard.lifespan import make_lifespan


@asynccontextmanager
async def my_lifespan(app):
    # your startup work
    yield
    # your shutdown work


app = FastAPI(lifespan=make_lifespan(my_lifespan))
app.add_middleware(SecurityMiddleware, config=config)
```

The host framework owns the lifespan: `guard_startup`
---------------------------------------------------------

Frameworks that wrap FastAPI - [NiceGUI](https://nicegui.io/), Chainlit, Gradio, and similar - own the `lifespan` slot internally and don't let you compose one in. They instead expose their own startup-hook registration API. For those, await `guard_startup(app)` from that hook:

```python
from nicegui import app, ui
from guard.lifespan import guard_startup
from guard.middleware import SecurityMiddleware
from guard_core.models import SecurityConfig

config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
app.add_middleware(SecurityMiddleware, config=config)


async def _warm_up_guard() -> None:
    await guard_startup(app)


app.on_startup(_warm_up_guard)

ui.run()
```

NiceGUI's `app.on_startup` takes the handler as an argument; it is not a decorator, so `@app.on_startup` is wrong (it returns `None` and rebinds your function). It runs once at app boot, from NiceGUI's FastAPI lifespan, before the server accepts connections, not per client (per client is `app.on_connect`). `guard_startup` performs exactly what `guard_lifespan` does on entry, so it is safe to call more than once: a second call adopts the already-warmed state instead of re-initializing, which keeps the once-at-boot goal safe even under NiceGUI's reload/restart. It is the supported approach whenever you cannot pass `lifespan=` to `FastAPI(...)` yourself.

OTEL and Logfire users benefit the most: without the lifespan helper their providers initialize on the first request; with it, providers are set at app boot, and the shared-state registry guarantees no duplicate `set_tracer_provider` call from the spawned-vs-live instance mismatch.

___

What's Next
-----------

- Learn about [IP Management](ip-management/banning.md)
- Configure [Rate Limiting](ip-management/rate-limiter.md)
- Set up [Penetration Detection](security/penetration-detection.md)
- Learn about [Redis Integration](redis-integration/caching.md)
