---

title: Rate Limiting Decorators - FastAPI Guard
description: Learn how to use rate limiting decorators for custom request rate controls and geographic rate limiting
keywords: rate limiting, request throttling, geographic limits, api rate control, security decorators
---

Rate Limiting Decorators
=========================

Rate limiting decorators allow you to apply custom rate limits to specific endpoints, overriding global settings and providing fine-grained control over request frequencies. These decorators help prevent abuse and ensure fair usage of your API resources.

___

Basic Rate Limiting
-------------------

Apply custom rate limits to specific routes:

. Simple Rate Limit
----------------------------

```python
from guard import SecurityConfig, SecurityDecorator

# geo source for block_countries, allow_countries and geo_rate_limit
config = SecurityConfig(
    ipinfo_token="your_ipinfo_token_here",
)
guard_deco = SecurityDecorator(config)


@app.get("/api/limited")
@guard_deco.rate_limit(requests=10, window=300)  # 10 requests per 5 minutes
def limited_endpoint():
    return {"data": "rate limited"}
```

. Override Global Settings
----------------------------

```python
# Global rate limit: 100 requests/hour
config = SecurityConfig(rate_limit=100, rate_limit_window=3600)


@app.get("/api/public")
def public_endpoint():
    # Uses global: 100 requests/hour
    return {"data": "public"}


@app.get("/api/strict")
@guard_deco.rate_limit(requests=5, window=300)  # Override: 5 requests/5min
def strict_endpoint():
    # Uses decorator: 5 requests/5min
    return {"data": "strictly limited"}
```

. Different Limits for Different Operations
-----------------------------------------

```python
@app.get("/api/read")
@guard_deco.rate_limit(requests=100, window=3600)  # 100 reads/hour
def read_data():
    return {"data": "read operation"}


@app.post("/api/write")
@guard_deco.rate_limit(requests=10, window=3600)  # 10 writes/hour
def write_data(data: dict):
    return {"status": "write operation"}


@app.delete("/api/delete")
@guard_deco.rate_limit(requests=5, window=3600)  # 5 deletes/hour
def delete_data():
    return {"status": "delete operation"}
```

___

Endpoint-Specific Rate Limits
-------------------

Tailor rate limits to endpoint sensitivity and usage patterns:

. Authentication Endpoints
------------------------

```python
@app.post("/auth/login")
@guard_deco.rate_limit(requests=5, window=300)  # 5 attempts per 5 minutes
def login(credentials: dict):
    return {"token": "jwt_token"}


@app.post("/auth/register")
@guard_deco.rate_limit(requests=3, window=3600)  # 3 registrations per hour
def register(user_data: dict):
    return {"status": "user created"}


@app.post("/auth/forgot-password")
@guard_deco.rate_limit(requests=2, window=3600)  # 2 reset requests per hour
def forgot_password(email: str):
    return {"status": "reset email sent"}
```

. Sensitive Operations
------------------------

```python
@app.post("/api/payment")
@guard_deco.rate_limit(requests=3, window=600)  # 3 payments per 10 minutes
def process_payment(payment_data: dict):
    return {"status": "payment processed"}


@app.post("/api/admin/user-ban")
@guard_deco.rate_limit(requests=10, window=3600)  # 10 bans per hour
def ban_user(user_id: str):
    return {"status": "user banned"}


@app.delete("/api/admin/data-purge")
@guard_deco.rate_limit(requests=1, window=86400)  # 1 purge per day
def purge_data():
    return {"status": "data purged"}
```

. Resource-Intensive Operations
-----------------------------

```python
@app.post("/api/export")
@guard_deco.rate_limit(requests=2, window=3600)  # 2 exports per hour
def export_data():
    return {"status": "export started"}


@app.post("/api/report/generate")
@guard_deco.rate_limit(requests=5, window=3600)  # 5 reports per hour
def generate_report():
    return {"status": "report generating"}


@app.post("/api/search/complex")
@guard_deco.rate_limit(requests=20, window=300)  # 20 searches per 5 minutes
def complex_search(query: dict):
    return {"results": "search results"}
```

___

Geographic Rate Limiting
-------------------------

Apply different rate limits based on user's geographic location:

. Country-Specific Limits
-----------------------

```python
@app.get("/api/content")
@guard_deco.geo_rate_limit(
    {
        "US": (100, 3600),  # 100 requests/hour for US
        "CA": (100, 3600),  # 100 requests/hour for Canada
        "GB": (80, 3600),  # 80 requests/hour for UK
        "DE": (80, 3600),  # 80 requests/hour for Germany
        "CN": (10, 3600),  # 10 requests/hour for China
        "*": (50, 3600),  # 50 requests/hour for others
    }
)
def geo_limited_content():
    return {"data": "geographic rate limited"}
```

. Tiered Geographic Access
------------------------

```python
@app.get("/api/premium")
@guard_deco.geo_rate_limit(
    {
        # Tier 1: Premium countries
        "US": (200, 3600),
        "CA": (200, 3600),
        "GB": (200, 3600),
        "DE": (200, 3600),
        "AU": (200, 3600),
        # Tier 2: Standard countries
        "FR": (100, 3600),
        "IT": (100, 3600),
        "ES": (100, 3600),
        "JP": (100, 3600),
        # Tier 3: Limited countries
        "IN": (50, 3600),
        "BR": (50, 3600),
        "MX": (50, 3600),
        # Default: Very limited
        "*": (20, 3600),
    }
)
def premium_content():
    return {"data": "premium geographic content"}
```

. Regional Business Hours
-----------------------

```python
@app.get("/api/support")
@guard_deco.geo_rate_limit(
    {
        # Higher limits during business hours in respective regions
        "US": (50, 3600),  # US business hours
        "EU": (40, 3600),  # European business hours
        "APAC": (30, 3600),  # Asia-Pacific business hours
        "*": (20, 3600),  # Outside business regions
    }
)
def support_endpoint():
    return {"data": "support information"}
```

___

Time-Based Rate Limiting
------------------------

Combine rate limiting with time windows:

. Business Hours vs After Hours
-----------------------------

```python
# Business hours: stricter limits
@app.post("/api/business/order")
@guard_deco.rate_limit(requests=50, window=3600)  # 50 orders/hour during business
@guard_deco.time_window("09:00", "17:00", "EST")
def business_hours_orders():
    return {"status": "business hours order"}


# After hours: more lenient
@app.post("/api/after-hours/order")
@guard_deco.rate_limit(requests=20, window=3600)  # 20 orders/hour after hours
def after_hours_orders():
    return {"status": "after hours order"}
```

. Weekend vs Weekday
------------------

```python
# Weekday: higher limits for business users
@app.get("/api/weekday/data")
@guard_deco.rate_limit(requests=100, window=3600)
def weekday_data():
    return {"data": "weekday business data"}


# Weekend: lower limits for personal use
@app.get("/api/weekend/data")
@guard_deco.rate_limit(requests=30, window=3600)
def weekend_data():
    return {"data": "weekend personal data"}
```

___

Advanced Rate Limiting Patterns
-------------------------------

. Graduated Rate Limits
---------------------

Different limits based on endpoint complexity:

```python
# Simple operations: Higher limits
@app.get("/api/simple/status")
@guard_deco.rate_limit(requests=1000, window=3600)
def simple_status():
    return {"status": "ok"}


# Medium operations: Moderate limits
@app.get("/api/medium/data")
@guard_deco.rate_limit(requests=100, window=3600)
def medium_data():
    return {"data": "medium complexity"}


# Complex operations: Low limits
@app.post("/api/complex/analysis")
@guard_deco.rate_limit(requests=10, window=3600)
def complex_analysis():
    return {"result": "complex analysis"}
```

. User Tier-Based Limits
----------------------

```python
# Free tier endpoints
@app.get("/api/free/data")
@guard_deco.rate_limit(requests=100, window=86400)  # 100 per day
def free_tier_data():
    return {"data": "free tier"}


# Premium tier endpoints
@app.get("/api/premium/data")
@guard_deco.rate_limit(requests=1000, window=3600)  # 1000 per hour
def premium_tier_data():
    return {"data": "premium tier"}


# Enterprise tier endpoints
@app.get("/api/enterprise/data")
@guard_deco.rate_limit(requests=10000, window=3600)  # 10000 per hour
def enterprise_tier_data():
    return {"data": "enterprise tier"}
```

. API Versioning Rate Limits
--------------------------

```python
# Legacy API: Restricted to encourage migration
@app.get("/api/v1/data")
@guard_deco.rate_limit(requests=50, window=3600)
def v1_data():
    return {"data": "legacy v1", "deprecated": True}


# Current API: Standard limits
@app.get("/api/v2/data")
@guard_deco.rate_limit(requests=100, window=3600)
def v2_data():
    return {"data": "current v2"}


# Beta API: Higher limits to encourage testing
@app.get("/api/v3/data")
@guard_deco.rate_limit(requests=200, window=3600)
def v3_data():
    return {"data": "beta v3"}
```

___

Combining with Other Decorators
-------------------------------

Stack rate limiting with other security measures:

. Rate Limiting + Access Control
------------------------------

```python
@app.post("/api/admin/action")
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])  # Internal network only
@guard_deco.rate_limit(requests=20, window=3600)  # 20 actions per hour
def admin_action():
    return {"status": "admin action completed"}
```

. Rate Limiting + Authentication
-----------------------------

```python
@app.get("/api/user/profile")
@guard_deco.require_auth(type="bearer")  # Authentication required
@guard_deco.rate_limit(requests=60, window=3600)  # 60 requests per hour
def user_profile():
    return {"profile": "user data"}
```

. Rate Limiting + Behavioral Analysis
----------------------------------

```python
@app.post("/api/game/action")
@guard_deco.rate_limit(requests=100, window=3600)  # 100 actions per hour
@guard_deco.usage_monitor(max_calls=50, window=300)  # Monitor for burst usage
def game_action():
    return {"result": "game action completed"}
```

___

Error Handling
--------------

Rate limiting decorators return specific HTTP status codes:

- **429 Too Many Requests**: Rate limit exceeded
- **503 Service Unavailable**: Rate limiting service unavailable

. Custom Rate Limit Messages
--------------------------

```python
config = SecurityConfig(
    custom_error_responses={429: "Rate limit exceeded. Please try again later."}
)

# The response will include rate limit headers:
# X-RateLimit-Limit: 10
# X-RateLimit-Remaining: 0
# X-RateLimit-Reset: 1640995200
```

___

Best Practices
--------------

. Match Limits to Endpoint Purpose
----------------------------------

Consider the business purpose and resource cost:

```python
# Good: High limits for lightweight operations
@guard_deco.rate_limit(requests=1000, window=3600)  # Status checks

# Good: Low limits for expensive operations
@guard_deco.rate_limit(requests=5, window=3600)     # Data exports

# Avoid: Same limits for all endpoints
```

. Consider User Experience
---------------------------

Don't make limits so strict they hurt legitimate users:

```python
# Good: Reasonable limits for normal usage
@guard_deco.rate_limit(requests=100, window=3600)   # Allows normal browsing

# Bad: Too restrictive for normal use
# @guard_deco.rate_limit(requests=5, window=3600)   # Hurts legitimate users
```

. Use Geographic Limits Thoughtfully
------------------------------------

Consider infrastructure and business presence:

```python
# Good: Higher limits where you have better infrastructure
@guard_deco.geo_rate_limit({
    "US": (200, 3600),  # Strong US presence
    "EU": (150, 3600),  # Good EU infrastructure
    "AS": (100, 3600),  # Developing APAC presence
})
```

. Provide Clear Error Messages
----------------------------

Help users understand the limits:

```python
config = SecurityConfig(
    custom_error_responses={
        429: "Rate limit exceeded. You can make 100 requests per hour. Current window resets at {reset_time}."
    }
)
```

___

Monitoring and Analytics
-----------------------

Track rate limiting effectiveness:

```python
# Enable detailed logging for rate limiting analysis
config = SecurityConfig(
    log_request_level="INFO",  # Log all requests
    log_suspicious_level="WARNING",  # Log rate limit violations
)

# Logs will show:
# "Rate limit exceeded for IP: 203.0.113.1"
# "Rate limit window reset for endpoint: /api/data"
```

___

Testing Rate Limits
-------------------

Test your rate limiting decorators:

```python
import pytest
from fastapi.testclient import TestClient
import time


def test_rate_limit():
    # Should allow requests within limit
    for _ in range(5):
        response = client.get("/api/limited")
        assert response.status_code == 200

    # Should block after limit exceeded
    response = client.get("/api/limited")
    assert response.status_code == 429

    # Should reset after window
    time.sleep(301)  # Wait for 5-minute window to reset
    response = client.get("/api/limited")
    assert response.status_code == 200
```

___

Next Steps
----------

Now that you understand rate limiting decorators, explore other security features:

- **[Access Control Decorators](access-control.md)** - IP and geographic restrictions
- **[Authentication Decorators](authentication.md)** - HTTPS and auth requirements
- **[Behavioral Analysis](behavioral.md)** - Monitor usage patterns
- **[Content Filtering](content-filtering.md)** - Request validation

For complete API reference, see the [Rate Limiting API Documentation](../../api/decorators.md#ratelimitingmixin).
