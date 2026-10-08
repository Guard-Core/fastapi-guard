---

title: Security Decorators Overview - FastAPI Guard
description: Learn how to use FastAPI Guard's security decorators for route-level protection and fine-grained security controls
keywords: security decorators, route protection, fastapi security, middleware decorators
---

Security Decorators Overview
=============================

FastAPI Guard's security decorators allow you to apply fine-grained security controls to individual routes, complementing the global middleware protection. This gives you the flexibility to customize security policies on a per-endpoint basis.

___

What are Security Decorators?
-----------------------------

Security decorators are Python decorators that you can apply to your FastAPI route functions to add specific security measures. They work alongside the global SecurityMiddleware to provide layered protection.

```python
from fastapi import FastAPI
from guard import SecurityConfig
from guard import SecurityDecorator

app = FastAPI()
config = SecurityConfig()
guard_deco = SecurityDecorator(config)


@app.get("/api/public")
def public_endpoint():
    return {"message": "This uses global security settings"}


@app.get("/api/restricted")
@guard_deco.rate_limit(requests=5, window=300)
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])
def restricted_endpoint():
    return {"message": "This has additional route-specific restrictions"}
```

___

Key Features
------------

- **Route-Level Controls**: Apply security rules to specific endpoints
- **Override Global Settings**: Route decorators can override global middleware settings
- **Stacking Support**: Combine multiple decorators for comprehensive protection
- **Behavioral Analysis**: Monitor endpoint usage patterns and detect anomalies
- **Content Filtering**: Control request types and sizes per endpoint
- **Time-Based Access**: Restrict access to specific time windows

___

Decorator Categories
--------------------

. Access Control
--------------

Control who can access your endpoints based on IP, geography, and cloud providers.

```python
@guard_deco.require_ip(whitelist=["192.168.1.0/24"])
@guard_deco.block_countries(["CN", "RU"])
@guard_deco.block_clouds(["AWS", "GCP"])
def sensitive_endpoint():
    return {"data": "restricted"}
```

. Authentication & Authorization
------------------------------

Enforce authentication requirements and secure headers.

```python
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
@guard_deco.api_key_auth(header_name="X-API-Key")
def authenticated_endpoint():
    return {"data": "authenticated"}
```

. Rate Limiting
-------------

Apply custom rate limits to specific endpoints.

```python
@guard_deco.rate_limit(requests=10, window=300)  # 10 requests per 5 minutes
@guard_deco.geo_rate_limit({"US": (100, 3600), "CN": (5, 3600)})
def limited_endpoint():
    return {"data": "rate limited"}
```

. Behavioral Analysis
-------------------

Monitor and analyze user behavior patterns.

```python
@guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")
@guard_deco.return_monitor("win", max_occurrences=3, window=86400, action="alert")
def game_endpoint():
    return {"result": "win", "reward": "rare_item"}
```

. Content Filtering
-----------------

Control request content and format.

```python
@guard_deco.content_type_filter(["application/json"])
@guard_deco.max_request_size(1024 * 1024)  # 1MB limit
@guard_deco.require_referrer(["myapp.com"])
def upload_endpoint():
    return {"status": "uploaded"}
```

. Advanced Features
-----------------

Time-based controls and sophisticated detection mechanisms.

```python
@guard_deco.time_window("09:00", "17:00", "UTC")  # Business hours only
@guard_deco.suspicious_detection(enabled=True)
@guard_deco.honeypot_detection(["bot_trap", "hidden_field"])
def advanced_endpoint():
    return {"data": "advanced protection"}
```

___

Basic Setup
-----------

. Initialize the Decorator
---------------------------

```python
from fastapi import FastAPI
from guard import SecurityMiddleware, SecurityConfig
from guard import SecurityDecorator

app = FastAPI()
config = SecurityConfig(
    enable_ip_banning=True,
    enable_rate_limiting=True,
    rate_limit=100,
    rate_limit_window=3600,
)

# Create decorator instance
guard_deco = SecurityDecorator(config)

# Add global middleware
app.add_middleware(SecurityMiddleware, config=config)

# IMPORTANT: Set decorator handler for integration
app.state.guard_decorator = guard_deco
```

. Apply Decorators to Routes
-----------------------------

```python
@app.post("/api/login")
@guard_deco.require_https()
@guard_deco.rate_limit(requests=5, window=300)  # Stricter limit for login
@guard_deco.suspicious_detection(enabled=True)
def login(credentials: dict):
    # Login logic here
    return {"token": "jwt_token"}


@app.get("/api/admin")
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])  # Internal network only
@guard_deco.require_auth(type="bearer")
@guard_deco.time_window("09:00", "17:00", "UTC")  # Business hours
def admin_panel():
    return {"message": "Admin access granted"}
```

___

Configuration Priority
----------------------

Security settings are applied in this order (highest to lowest priority):

1. Decorator Settings - Route-specific configurations
2. Global Middleware Settings - Application-wide defaults
3. Built-in Defaults - Library defaults

This allows flexible overrides where routes can customize their security while maintaining global baselines.

```python
# Global: 100 requests/hour
config = SecurityConfig(rate_limit=100, rate_limit_window=3600)


@app.get("/api/public")
def public_endpoint():
    # Uses global: 100 requests/hour
    return {"data": "public"}


@app.get("/api/limited")
@guard_deco.rate_limit(requests=10, window=300)  # Override: 10 requests/5min
def limited_endpoint():
    # Uses decorator: 10 requests/5min
    return {"data": "limited"}
```

___

Decorator Visibility Shapes the Security Pipeline
----------------------------------------------------

!!! info "Pipeline visibility (guard-core 3.10.0+)"
    Wiring `app.state.guard_decorator` does more than route decorator settings to the middleware. guard-core 3.10.0 builds the security pipeline from the effective configuration and skips checks that configuration can never trigger. Six of those checks (including `require_auth`, `require_referrer`, and `time_window`) are driven purely by per-route decorator settings, and guard-core can only skip them when it can enumerate the registered route configuration through the middleware's `guard_decorator`. `SecurityMiddleware` resolves `app.state.guard_decorator` before it builds the pipeline, and `guard_lifespan`, `make_lifespan`, and `guard_startup` all resolve it the same way at startup. When no decorator handler can be found, route configuration is treated as unknown and every route-driven check is kept, so a missed wiring step can only lose the smaller pipeline, never the protection those checks provide. This is separate from [behavioral rule firing](behavioral.md), which uses the same wiring but evaluates rules on every request rather than shaping which checks exist.

___

Routers and Mounted Applications
---------------------------------

Decorators fire wherever the route lives. `SecurityMiddleware` runs before FastAPI's router, so it matches the request against the app's route table itself, descending through `include_router()` wrappers and `mount()`ed sub-applications to find the endpoint that will handle the request.

```python
admin = APIRouter(prefix="/admin")
billing = APIRouter(prefix="/billing")


@billing.get("/invoices")
@guard_deco.require_auth(type="bearer")
def invoices():
    return {"invoices": []}


admin.include_router(billing)
app.include_router(admin, prefix="/v1")  # /v1/admin/billing/invoices
```

There is no nesting limit. Routers included into routers, sub-applications mounted into sub-applications, and any mix of the two all resolve, and the decorator on `invoices` is enforced at whatever depth it ends up.

!!! warning "Versions before 7.3.1"
    Route resolution stopped after eight levels of mounts, and never descended past one level of `include_router()`. Decorators on routes below those limits silently did nothing — including `require_auth`, which meant an endpoint served unauthenticated. See [GHSA-f2vm-w8gq-h378](https://github.com/Guard-Core/fastapi-guard/security/advisories/GHSA-f2vm-w8gq-h378). If you compose your app from nested routers or mounts, upgrade.

A request that reaches a mounted application guard-core does not route for — `StaticFiles`, a WSGI app, any opaque ASGI app — has no endpoint to decorate, so per-route checks do not apply to it and global `SecurityConfig` settings govern instead.

___

Best Practices
--------------

. Logical Decorator Order
--------------------------

Apply decorators from most specific to most general:

```python
@app.post("/api/admin/sensitive")
@guard_deco.require_https()  # Security requirement
@guard_deco.require_auth(type="bearer")  # Authentication
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])  # Access control
@guard_deco.rate_limit(requests=5, window=3600)  # Rate limiting
@guard_deco.suspicious_detection(enabled=True)  # Monitoring
def admin_endpoint():
    return {"status": "admin action"}
```

. Combine Related Decorators
-----------------------------

Group related security measures:

```python
# Geographic restrictions
@guard_deco.allow_countries(["US", "CA", "GB"])
@guard_deco.block_clouds(["AWS", "GCP"])

# Content controls
@guard_deco.content_type_filter(["image/jpeg", "image/png"])
@guard_deco.max_request_size(5 * 1024 * 1024)

# Behavioral monitoring
@guard_deco.usage_monitor(max_calls=50, window=3600)
@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400)
```

. Error Handling
-----------------

Decorators integrate with middleware error handling:

- **403 Forbidden**: IP restrictions, country blocks, auth failures
- **429 Too Many Requests**: Rate limiting violations
- **400 Bad Request**: Content type mismatches, missing headers
- **413 Payload Too Large**: Request size exceeded

___

Next Steps
----------

Now that you understand the overview, dive deeper into specific decorator categories:

- **[Access Control](access-control.md)** - IP filtering and geographic restrictions
- **[Authentication](authentication.md)** - HTTPS, auth requirements, and API keys
- **[Rate Limiting](rate-limiting.md)** - Custom rate limits and geographic limits
- **[Behavioral Analysis](behavioral.md)** - Usage monitoring and anomaly detection
- **[Content Filtering](content-filtering.md)** - Request validation and content controls
- **[Advanced Features](advanced.md)** - Time windows and sophisticated detection

For complete API reference, see the [Security Decorators API Documentation](../../api/decorators.md).
