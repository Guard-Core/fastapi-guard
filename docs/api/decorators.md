---

title: Security Decorators API - FastAPI Guard
description: API reference for managing security decorators in FastAPI Guard
keywords: security decorators, fastapi guard, security middleware, python api reference
---

Security Decorators
======================

The decorators module provides route-level security controls that can be applied to individual FastAPI endpoints. These decorators offer fine-grained control over security policies on a per-route basis, complementing the global middleware security features.

___

Overview
---------------

Security decorators allow you to:

- Apply specific security rules to individual routes
- Override global security settings for specific endpoints
- Combine multiple security measures in a clean, readable way
- Implement behavioral analysis and monitoring per endpoint

___

Main Decorator Class
---------------

. SecurityDecorator
----------------------------

::: guard_core.decorators.SecurityDecorator

The main decorator class that combines all security capabilities. This is the primary class you'll use in your application.

**Example Usage:**

```python
from fastapi import FastAPI
from guard import SecurityConfig
from guard import SecurityDecorator

app = FastAPI()
config = SecurityConfig(
    # geo source for block_countries, allow_countries and geo_rate_limit; response body scanning for return_monitor
    ipinfo_token="your_ipinfo_token_here",
    behavior_scan_response_body=True,
)
guard_deco = SecurityDecorator(config)


@app.get("/api/sensitive")
@guard_deco.rate_limit(requests=5, window=300)
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])
@guard_deco.block_countries(["CN", "RU"])
def sensitive_endpoint():
    return {"data": "sensitive"}
```

___

Base Classes
------------

. BaseSecurityDecorator
---------------------

::: guard_core.decorators.base.BaseSecurityDecorator

Base class providing core decorator functionality and route configuration management.

. RouteConfig
---------------------

::: guard_core.decorators.base.RouteConfig

Configuration class that stores security settings for individual routes.

___

Mixin Classes
-------------

The decorator system uses mixins to organize different types of security features:

. AccessControlMixin
---------------------

::: guard_core.decorators.access_control.AccessControlMixin

Provides IP-based and geographic access control decorators.

**Available Decorators:**

- `@guard_deco.require_ip(whitelist=[], blacklist=[])` - IP address filtering
- `@guard_deco.block_countries(countries=[])` - Block specific countries
- `@guard_deco.allow_countries(countries=[])` - Allow only specific countries
- `@guard_deco.block_clouds(providers=[])` - Block cloud provider IPs
- `@guard_deco.bypass(checks=[])` - Bypass specific security checks

. AuthenticationMixin
---------------------

::: guard_core.decorators.authentication.AuthenticationMixin

Provides authentication and authorization decorators.

**Available Decorators:**

- `@guard_deco.require_https()` - Force HTTPS
- `@guard_deco.require_auth(type="bearer", verifier=None)` - Require authentication. `verifier` is a callable `verifier(request, credential) -> Principal | None` that validates the credential and returns a principal; if omitted, the global `SecurityConfig.auth_verifier` is used; if neither is set, the request is rejected with 401 fail-closed. The principal is stashed on `request.state.auth_principal`. Mutually exclusive with `require_authorization_header`.
- `@guard_deco.api_key_auth(header_name="X-API-Key", verifier=None)` - API key authentication. `verifier` resolves the same way as `require_auth` (per-route, then `SecurityConfig.auth_verifier`, then 401 fail-closed). Mutually exclusive with `require_authorization_header`.
- `@guard_deco.require_authorization_header(scheme="bearer")` - Presence-only header gate. Checks that the `Authorization` header is present and starts with the given scheme. Documented as NOT authentication: no verifier is consulted and no principal is stashed. Mutually exclusive with `require_auth` and `api_key_auth` (combining raises `ValueError` at decoration time). This is the renamed old behavior of `require_auth`.
- `@guard_deco.require_headers(headers={})` - Require specific headers

`SecurityConfig.auth_verifier` is the global default verifier for every `require_auth` and `api_key_auth` route that does not pass its own `verifier=`. In ASGI it may be sync or async.

. RateLimitingMixin
---------------------

::: guard_core.decorators.rate_limiting.RateLimitingMixin

Provides rate limiting decorators.

**Available Decorators:**

- `@guard_deco.rate_limit(requests=10, window=60)` - Basic rate limiting
- `@guard_deco.geo_rate_limit(limits={})` - Geographic rate limiting

. BehavioralMixin
---------------------

::: guard_core.decorators.behavioral.BehavioralMixin

Provides behavioral analysis and monitoring decorators.

**Available Decorators:**

- `@guard_deco.usage_monitor(max_calls, window, action)` - Monitor endpoint usage
- `@guard_deco.return_monitor(pattern, max_occurrences, window, action)` - Monitor return patterns
- `@guard_deco.behavior_analysis(rules=[])` - Apply multiple behavioral rules
- `@guard_deco.suspicious_frequency(max_frequency, window, action)` - Detect suspicious frequency

. ContentFilteringMixin
---------------------

::: guard_core.decorators.content_filtering.ContentFilteringMixin

Provides content and request filtering decorators.

**Available Decorators:**

- `@guard_deco.block_user_agents(patterns=[])` - Block user agent patterns
- `@guard_deco.content_type_filter(allowed_types=[])` - Filter content types
- `@guard_deco.max_request_size(size_bytes)` - Limit request size
- `@guard_deco.require_referrer(allowed_domains=[])` - Require specific referrers
- `@guard_deco.custom_validation(validator)` - Add custom validation logic
- `@guard_deco.detection_exclusion(headers=None, params=None, body_fields=None, categories=None, scan_body=None)` - Exclude specific headers/params/body fields or detection categories from penetration detection on this route

. AdvancedMixin
-------------

::: guard_core.decorators.advanced.AdvancedMixin

Provides advanced detection and time-based decorators.

**Available Decorators:**

- `@guard_deco.time_window(start_time, end_time, timezone)` - Time-based access control
- `@guard_deco.suspicious_detection(enabled=True)` - Toggle suspicious pattern detection
- `@guard_deco.honeypot_detection(trap_fields=[])` - Detect bots using honeypot fields

___

Utility Functions
-----------------

. get_route_decorator_config
---------------------------

::: guard_core.decorators.base.get_route_decorator_config

Extract route security configuration from the current FastAPI request.

___

Integration with Middleware
---------------------------

The decorators work in conjunction with the SecurityMiddleware to provide comprehensive protection:

1. **Route Configuration**: Decorators configure route-specific settings
2. **Middleware Processing**: SecurityMiddleware reads decorator configurations and applies them
3. **Override Behavior**: Route-specific settings can override global middleware settings

**Example Integration:**

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
    # geo source for block_countries, allow_countries and geo_rate_limit; response body scanning for return_monitor
    ipinfo_token="your_ipinfo_token_here",
    behavior_scan_response_body=True,
)

# Create decorator instance
guard_deco = SecurityDecorator(config)


# Apply decorators to routes
@guard_deco.rate_limit(requests=10, window=300)  # Override: 10 requests/5min
@app.get("/api/limited")
def limited_endpoint():
    # Uses decorator-specific rate limiting
    return {"data": "limited"}


@app.get("/api/public")
def public_endpoint():
    # Uses global rate limiting (100 requests/hour)
    return {"data": "public"}


# Add global middleware
app.add_middleware(SecurityMiddleware, config=config)

# Set decorator handler on app state (required for integration)
app.state.guard_decorator = guard_deco
```

___

Best Practices
--------------

. Decorator Order
---------------------

Apply decorators in logical order, with more specific restrictions first:

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

. Combining Behavioral Analysis
---------------------

Use multiple behavioral decorators for comprehensive monitoring:

```python
@app.get("/api/rewards")
@guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")
@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400, action="ban")
@guard_deco.suspicious_frequency(max_frequency=0.1, window=300, action="alert")
def rewards_endpoint():
    return {"reward": "rare_item", "value": 1000}
```

. Geographic and Cloud Controls
---------------------

Combine geographic and cloud provider controls:

```python
@app.get("/api/restricted")
@guard_deco.allow_countries(["US", "CA", "GB"])  # Allow specific countries
@guard_deco.block_clouds(["AWS", "GCP"])  # Block cloud providers
def restricted_endpoint():
    return {"data": "geo-restricted"}
```

. Content Filtering
---------------------

Apply content filtering for upload endpoints:

```python
@app.post("/api/upload")
@guard_deco.content_type_filter(["image/jpeg", "image/png"])
@guard_deco.max_request_size(5 * 1024 * 1024)  # 5MB limit
@guard_deco.require_referrer(["myapp.com"])
def upload_endpoint():
    return {"status": "uploaded"}
```

___

Error Handling
--------------

Decorators integrate with the middleware's error handling system. When decorator conditions are not met, appropriate HTTP responses are returned:

. 403 Forbidden
---------------------

IP restrictions, country blocks, authentication failures

. 429 Too Many Requests
---------------------

Rate limiting violations

. 400 Bad Request
---------------------

Content type mismatches, missing headers

. 413 Payload Too Large
---------------------

Request size limits exceeded

___

Configuration Priority
--------------

Security settings are applied in the following priority order:

1. Decorator Settings (highest priority)
2. Global Middleware Settings
3. Default Settings (lowest priority)

This allows for flexible override behavior where routes can customize their security requirements while maintaining global defaults.

For IP and country access control, this priority applies per-aspect rather than as a blanket override: the global IP whitelist/blacklist and country rules always run on decorated routes. A route-level allow rule (`ip_whitelist` or `whitelist_countries`) suppresses the corresponding global gate. A route-level deny rule (`ip_blacklist` or `blocked_countries`) is additive and does not disable the global rules. Within the IP aspect, a route `ip_whitelist` match takes priority over that route's own `ip_blacklist` and over the global blacklist.
