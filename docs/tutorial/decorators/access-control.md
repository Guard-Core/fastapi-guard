---

title: Access Control Decorators - FastAPI Guard
description: Learn how to use access control decorators for IP filtering, geographic restrictions, and cloud provider blocking
keywords: access control, ip filtering, geographic restrictions, cloud blocking, security decorators
---

Access Control Decorators
==========================

Access control decorators allow you to restrict access to specific endpoints based on IP addresses, geographic location, and cloud providers. These decorators provide fine-grained control over who can access your routes.

___

IP Address Filtering
--------------------

Control access based on specific IP addresses or CIDR ranges:

. IP Whitelist
------------

Only allow access from specific IP addresses:

```python
from guard import SecurityConfig, SecurityDecorator

# geo source for block_countries, allow_countries and geo_rate_limit
config = SecurityConfig(
    ipinfo_token="your_ipinfo_token_here",
)
guard_deco = SecurityDecorator(config)


@app.get("/api/internal")
@guard_deco.require_ip(whitelist=["192.168.1.0/24", "10.0.0.1"])
def internal_endpoint():
    return {"message": "Internal network access only"}
```

. IP Blacklist
------------

Block specific IP addresses while allowing others:

```python
@app.get("/api/public")
@guard_deco.require_ip(blacklist=["203.0.113.0/24", "198.51.100.1"])
def public_endpoint():
    return {"message": "Public access except blocked IPs"}
```

. Combined IP Rules
-----------------

Use both whitelist and blacklist together:

```python
@app.get("/api/restricted")
@guard_deco.require_ip(
    whitelist=["192.168.0.0/16"],  # Allow internal network
    blacklist=["192.168.1.100"],  # Except this specific IP
)
def restricted_endpoint():
    return {"data": "Carefully controlled access"}
```

___

Geographic Restrictions
-----------------------

Control access based on user's country location:

. Block Specific Countries
------------------------

Prevent access from certain countries:

```python
@app.get("/api/compliance-sensitive")
@guard_deco.block_countries(["CN", "RU", "IR", "KP"])
def compliance_endpoint():
    return {"data": "Compliance-restricted content"}
```

. Allow Only Specific Countries
-----------------------------

Restrict access to certain countries only:

```python
@app.get("/api/us-only")
@guard_deco.allow_countries(["US"])
def us_only_endpoint():
    return {"data": "US-only content"}


@app.get("/api/eu-only")
@guard_deco.allow_countries(["GB", "DE", "FR", "IT", "ES", "NL"])
def eu_only_endpoint():
    return {"data": "EU-only content"}
```

. Regional Access
---------------

Create region-specific endpoints:

```python
@app.get("/api/north-america")
@guard_deco.allow_countries(["US", "CA", "MX"])
def north_america_endpoint():
    return {"data": "North America region"}


@app.get("/api/asia-pacific")
@guard_deco.allow_countries(["JP", "KR", "AU", "SG", "IN"])
def asia_pacific_endpoint():
    return {"data": "Asia-Pacific region"}
```

___

Cloud Provider Blocking
------------------------

Block requests originating from cloud provider IP ranges:

. Block Specific Cloud Providers
-----------------------------

```python
@app.get("/api/no-clouds")
@guard_deco.block_clouds(["AWS", "GCP"])
def no_clouds_endpoint():
    return {"data": "No cloud provider access"}
```

. Block All Major Cloud Providers
-------------------------------

```python
@app.get("/api/residential-only")
@guard_deco.block_clouds(["AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"])
def residential_only_endpoint():
    return {"data": "Residential IP addresses only"}
```

. Block All Supported Clouds
--------------------------

```python
@app.get("/api/anti-automation")
@guard_deco.block_clouds()  # Blocks all supported cloud providers
def anti_automation_endpoint():
    return {"data": "No automated/cloud access"}
```

___

Bypassing Security Checks
-------------------------

Selectively disable specific security checks for certain routes:

. Valid Bypass Tokens
-------------------

| Token | Skips |
|---|---|
| `all` | The entire security pipeline for the route |
| `ip_ban` | The standing banned-IP check |
| `ip` | Global IP whitelist/blacklist, blocked countries and blocked clouds |
| `clouds` | The cloud provider check |
| `rate_limit` | Global, endpoint, route and geo rate limiting |
| `penetration` | Detection engine / suspicious activity |

An unknown token is ignored and logged as a warning naming it, so a typo leaves the check fully enforced rather than raising. There is no country-only token: country blocking is bypassed by `ip`, which also lifts the global IP whitelist and blacklist for that route.

. Bypass Specific Checks
----------------------

```python
@app.get("/api/health")
@guard_deco.bypass(["rate_limit", "ip"])  # Bypass rate limiting and IP checks
def health_check():
    return {"status": "healthy"}
```

. Bypass All Security
-------------------

```python
@app.get("/api/public-health")
@guard_deco.bypass(["all"])  # Bypass all security checks
def public_health_check():
    return {"status": "public health endpoint"}
```

. Common Bypass Scenarios
-----------------------

```python
# Monitoring endpoint - bypass rate limits
@app.get("/metrics")
@guard_deco.bypass(["rate_limit"])
def metrics():
    return {"metrics": "data"}


# Public API documentation - bypass IP, country and cloud restrictions
@app.get("/docs-public")
@guard_deco.bypass(["ip"])
def public_docs():
    return {"docs": "public documentation"}
```

___

Combining Access Controls
-------------------------

Stack multiple access control decorators for comprehensive protection:

. Multi-Layer Protection
----------------------

```python
@app.post("/api/admin/sensitive")
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])  # Internal network only
@guard_deco.allow_countries(["US", "CA"])  # North America only
@guard_deco.block_clouds(["AWS", "GCP"])  # No cloud providers
def ultra_secure_endpoint():
    return {"data": "Maximum security endpoint"}
```

. Tiered Access Control
---------------------

```python
# High-security financial endpoint
@app.post("/api/financial/transfer")
@guard_deco.require_ip(whitelist=["192.168.1.0/24"])  # Company network only
@guard_deco.allow_countries(["US"])  # US jurisdiction only
@guard_deco.block_clouds()  # No cloud/automation
def financial_transfer():
    return {"status": "transfer initiated"}


# Medium-security user data
@app.get("/api/user/profile")
@guard_deco.block_countries(["CN", "RU", "IR"])  # Block certain countries
@guard_deco.block_clouds(["AWS", "GCP"])  # Block major clouds
def user_profile():
    return {"profile": "user data"}


# Low-security public content
@app.get("/api/public/content")
@guard_deco.block_clouds(["DigitalOcean"])  # Block only specific providers
def public_content():
    return {"content": "public information"}
```

___

Advanced Patterns
-----------------

. Geographic Failover
-------------------

Allow broader access if primary regions fail:

```python
@app.get("/api/primary")
@guard_deco.allow_countries(["US", "CA"])
def primary_endpoint():
    return {"region": "primary"}


@app.get("/api/fallback")
@guard_deco.allow_countries(["GB", "DE", "AU"])
def fallback_endpoint():
    return {"region": "fallback"}
```

. Time-Based Geographic Access
----------------------------

Different geographic rules for different times:

```python
from datetime import datetime


# Business hours: strict geographic controls
@app.get("/api/business-hours")
@guard_deco.allow_countries(["US"])
@guard_deco.time_window("09:00", "17:00", "EST")
def business_hours_endpoint():
    return {"data": "business hours access"}


# After hours: more lenient
@app.get("/api/after-hours")
@guard_deco.allow_countries(["US", "CA", "GB"])
def after_hours_endpoint():
    return {"data": "after hours access"}
```

___

Error Handling
--------------

Access control decorators return specific HTTP status codes:

- **403 Forbidden**: IP not in whitelist, IP in blacklist
- **403 Forbidden**: Country blocked or not in allowed list
- **403 Forbidden**: Cloud provider IP detected and blocked

. Custom Error Messages
---------------------

```python
# The middleware will use custom error messages if configured
config = SecurityConfig(
    custom_error_responses={403: "Access denied: Geographic restrictions apply"}
)
```

___

Best Practices
--------------

. Start Restrictive, Then Open Up
-------------------------------

Begin with strict controls and gradually relax as needed:

```python
# Start with company network only
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])

# Then add specific external IPs
@guard_deco.require_ip(whitelist=["10.0.0.0/8", "203.0.113.100"])

# Finally add geographic controls
@guard_deco.allow_countries(["US", "CA"])
```

. Layer Different Types of Controls
---------------------------------

Combine IP, geographic, and cloud controls for defense in depth:

```python
@guard_deco.require_ip(whitelist=["192.168.0.0/16"])   # Internal network
@guard_deco.allow_countries(["US"])                    # US only
@guard_deco.block_clouds()                             # No automation
```

. Use Bypass Strategically
------------------------

Only bypass security for truly public endpoints:

```python
# Good: Health checks need to work from monitoring systems
@guard_deco.bypass(["rate_limit"])

# Bad: Don't bypass security for sensitive data
# @guard_deco.bypass(["all"])  # Avoid this for sensitive endpoints
```

. Test Geographic Controls
------------------------

Test with VPN connections from different countries to verify behavior:

```python
# Ensure your geographic controls work as expected
@guard_deco.allow_countries(["US", "CA"])
# Test: Connect via VPN from blocked country, should get 403
```

___

Troubleshooting
--------------

. Common Issues
-------------

1. VPN/Proxy Detection: Users behind VPNs may be incorrectly geo-located
2. Cloud Provider Classification: Some legitimate users may come from cloud IPs
3. IP Range Conflicts: Overlapping whitelist/blacklist rules

. Debugging Tips
--------------

```python
# Enable detailed logging to see why access was denied
config = SecurityConfig(log_suspicious_level="DEBUG", log_request_level="INFO")

# Check logs for messages like:
# "IP not allowed by route config: 203.0.113.1"
# "Blocked cloud provider IP: 54.239.28.85"
```

___

Next Steps
----------

Now that you understand access control decorators, explore other security features:

- **[Authentication Decorators](authentication.md)** - HTTPS and auth requirements
- **[Rate Limiting Decorators](rate-limiting.md)** - Custom rate controls
- **[Behavioral Analysis](behavioral.md)** - Monitor usage patterns
- **[Content Filtering](content-filtering.md)** - Request validation

For complete API reference, see the [Access Control API Documentation](../../api/decorators.md#accesscontrolmixin).
