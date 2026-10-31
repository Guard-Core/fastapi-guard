---

title: HTTP Security Headers - FastAPI Guard Tutorial
description: Configure and use security headers following OWASP best practices with FastAPI Guard
keywords: security headers tutorial, CSP configuration, HSTS setup, X-Frame-Options

---

HTTP Security Headers
=====================

FastAPI Guard provides comprehensive HTTP security header management to protect your application from various web vulnerabilities. This tutorial covers how to configure and use security headers following OWASP best practices.

___

Overview
--------

Security headers are HTTP response headers that provide an additional layer of security by instructing browsers on how to handle your application's content. FastAPI Guard automatically manages these headers through the `SecurityHeadersManager`.

___

Quick Start
-----------

Basic Setup
-----------

Enable security headers with default OWASP-recommended settings:

```python
from fastapi import FastAPI
from guard import SecurityMiddleware, SecurityConfig

app = FastAPI()

config = SecurityConfig(
    security_headers={
        "enabled": True  # Uses secure defaults
    }
)

app.add_middleware(SecurityMiddleware, config=config)
```

This automatically adds:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `X-XSS-Protection: 0`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`
- `X-Permitted-Cross-Domain-Policies: none`
- `X-Download-Options: noopen`
- `Cross-Origin-Embedder-Policy` is not sent unless you set `cross_origin_embedder_policy`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-site`

Advanced Configuration
----------------------

```python
config = SecurityConfig(
    security_headers={
        "enabled": True,
        "hsts": {
            "max_age": 31536000,  # 1 year
            "include_subdomains": True,
            "preload": False,
        },
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://cdn.jsdelivr.net"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:", "https:"],
        },
        "frame_options": "DENY",
        "referrer_policy": "no-referrer",
    }
)
```

___

Content Security Policy (CSP)
------------------------------

CSP is one of the most powerful security headers, preventing XSS attacks by controlling which resources can be loaded.

Basic CSP
---------

```python
config = SecurityConfig(
    security_headers={
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'"],
            "img-src": ["'self'", "data:"],
        }
    }
)
```

Progressive CSP Implementation
------------------------------

Start with a permissive policy and gradually tighten:

```python
# Step 1: Permissive policy
config = SecurityConfig(
    security_headers={
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'unsafe-inline'"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "report-uri": ["/api/csp-report"],
        }
    }
)

# Step 2: Remove unsafe-inline for scripts
config = SecurityConfig(
    security_headers={
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'", "'unsafe-inline'"],
        }
    }
)

# Step 3: Strict CSP
config = SecurityConfig(
    security_headers={
        "csp": {
            "default-src": ["'none'"],
            "script-src": ["'self'"],
            "style-src": ["'self'"],
            "img-src": ["'self'"],
            "connect-src": ["'self'"],
            "font-src": ["'self'"],
            "base-uri": ["'self'"],
            "form-action": ["'self'"],
            "frame-ancestors": ["'none'"],
            "upgrade-insecure-requests": [],
        }
    }
)
```

CSP for Single Page Applications
---------------------------------

```python
config = SecurityConfig(
    security_headers={
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'", "'unsafe-inline'"],  # For dynamic styles
            "img-src": ["'self'", "data:", "https:"],
            "connect-src": ["'self'", "https://api.example.com"],
            "font-src": ["'self'", "https://fonts.gstatic.com"],
            "frame-ancestors": ["'none'"],
            "base-uri": ["'self'"],
        }
    }
)
```

CSP Violation Reporting
-----------------------

Set up an endpoint to receive CSP violation reports:

```python
from fastapi import Request


@app.post("/api/csp-report")
async def csp_report(request: Request):
    from guard import security_headers_manager

    report = await request.json()
    is_valid = await security_headers_manager.validate_csp_report(report)

    if is_valid:
        # Log the violation (handled automatically)
        return {"status": "received"}

    return {"status": "invalid"}, 400


# Configure CSP with reporting
config = SecurityConfig(
    security_headers={
        "csp": {"default-src": ["'self'"], "report-uri": ["/api/csp-report"]}
    }
)
```

___

HTTP Strict Transport Security (HSTS)
---------------------------------------

HSTS ensures that browsers only connect to your site over HTTPS.

Basic HSTS
----------

```python
config = SecurityConfig(
    security_headers={
        "hsts": {
            "max_age": 31536000,  # 1 year
            "include_subdomains": True,
            "preload": False,
        }
    }
)
```

HSTS Rollout Strategy
---------------------

```python
# Phase 1: Short duration (5 minutes)
config = SecurityConfig(
    security_headers={
        "hsts": {"max_age": 300, "include_subdomains": False, "preload": False}
    }
)

# Phase 2: Longer duration (1 week)
config = SecurityConfig(
    security_headers={
        "hsts": {"max_age": 604800, "include_subdomains": True, "preload": False}
    }
)

# Phase 3: Production (1 year + preload)
config = SecurityConfig(
    security_headers={
        "hsts": {
            "max_age": 31536000,  # Required for preload
            "include_subdomains": True,  # Required for preload
            "preload": True,
        }
    }
)
```

___

Clickjacking Protection
------------------------

Prevent your site from being embedded in frames:

```python
# Option 1: Deny all framing
config = SecurityConfig(security_headers={"frame_options": "DENY"})

# Option 2: Allow same-origin framing
config = SecurityConfig(security_headers={"frame_options": "SAMEORIGIN"})

# Option 3: Use CSP frame-ancestors (more flexible)
config = SecurityConfig(
    security_headers={
        "frame_options": None,  # Disable X-Frame-Options
        "csp": {"frame-ancestors": ["'self'", "https://trusted.example.com"]},
    }
)
```

___

CORS and Security Headers
--------------------------

Security headers work alongside CORS configuration:

```python
config = SecurityConfig(
    enable_cors=True,
    cors_allow_origins=["https://app.example.com"],
    cors_allow_credentials=True,
    cors_allow_methods=["GET", "POST"],
    cors_allow_headers=["*"],
    security_headers={
        "enabled": True,
        "csp": {
            "default-src": ["'self'"],
            "connect-src": ["'self'", "https://app.example.com"],
        },
    },
)
```

___

Custom Headers
--------------

Add application-specific security headers:

```python
config = SecurityConfig(
    security_headers={
        "custom": {
            "X-Permitted-Cross-Domain-Policies": "none",
            "X-Download-Options": "noopen",
            "X-DNS-Prefetch-Control": "off",
            "X-Robots-Tag": "noindex, nofollow",
        }
    }
)
```

___

Environment-Specific Configuration
-----------------------------------

Different headers for development and production:

```python
import os

is_production = os.getenv("ENVIRONMENT") == "production"

config = SecurityConfig(
    security_headers={
        "enabled": True,
        "hsts": {
            "max_age": 31536000 if is_production else 0,
            "include_subdomains": is_production,
            "preload": is_production,
        },
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'"] + ([] if is_production else ["'unsafe-inline'"]),
            "style-src": ["'self'", "'unsafe-inline'"],
        }
        if is_production
        else None,  # Disable CSP in development
    }
)
```

___

Redis Integration
-----------------

Security headers configuration is cached in Redis for performance:

```python
config = SecurityConfig(
    enable_redis=True,
    redis_url="redis://localhost:6379",
    security_headers={"enabled": True, "csp": {"default-src": ["'self'"]}},
)

# Headers are cached with TTL of 24 hours
# Cache keys:
# - security_headers:csp_config
# - security_headers:hsts_config
# - security_headers:custom_headers
```

___

Testing Security Headers
------------------------

Using curl
----------

```bash
# Check security headers
curl -I https://your-app.com

# Check CSP header
curl -I https://your-app.com | grep -i content-security-policy

# Test CORS headers
curl -H "Origin: https://app.example.com" \
     -I https://your-app.com
```

Automated Testing
-----------------

```python
import pytest
from fastapi.testclient import TestClient


def test_security_headers(client: TestClient):
    response = client.get("/")

    # Check essential headers
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert "strict-origin" in response.headers.get("Referrer-Policy", "")

    # Check HSTS
    hsts = response.headers.get("Strict-Transport-Security", "")
    assert "max-age=31536000" in hsts

    # Check CSP
    csp = response.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp


def test_csp_violation_reporting(client: TestClient):
    report = {
        "csp-report": {
            "document-uri": "https://example.com",
            "violated-directive": "script-src",
            "blocked-uri": "https://evil.com/script.js",
        }
    }

    response = client.post("/api/csp-report", json=report)
    assert response.status_code == 200
```

___

Monitoring and Debugging
------------------------

Enable Logging
--------------

```python
import logging

# Configure logging for security headers
logging.getLogger("guard_core.handlers.security_headers").setLevel(logging.DEBUG)

config = SecurityConfig(
    custom_log_file="security.log", security_headers={"enabled": True}
)
```

Agent Integration
-----------------

Monitor security header events with FastAPI Guard Agent:

```python
config = SecurityConfig(
    enable_agent=True,
    agent_api_key="your-api-key",
    security_headers={
        "enabled": True,
        "csp": {"default-src": ["'self'"], "report-uri": ["/api/csp-report"]},
    },
)

# Events sent to agent:
# - security_headers_applied: When headers are added
# - csp_violation: When CSP violations occur
```

___

Common Issues and Solutions
---------------------------

Issue: Inline Scripts Blocked by CSP
-------------------------------------

**Solution**: Use external scripts

```html
<!-- Instead of inline -->
<script>console.log('Hello')</script>

<!-- Use external -->
<script src="/static/app.js"></script>
```

Or allow unsafe-inline in your CSP configuration (less secure):

```python
config = SecurityConfig(
    security_headers={"csp": {"script-src": ["'self'", "'unsafe-inline'"]}}
)
```

Issue: Third-Party Resources Blocked
-------------------------------------

**Solution**: Add specific sources to CSP

```python
config = SecurityConfig(
    security_headers={
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://cdn.jsdelivr.net"],
            "style-src": ["'self'", "https://fonts.googleapis.com"],
            "font-src": ["'self'", "https://fonts.gstatic.com"],
        }
    }
)
```

Issue: HSTS Causing Access Issues
----------------------------------

**Solution**: Start with short max_age

```python
# Start with 5 minutes
config = SecurityConfig(security_headers={"hsts": {"max_age": 300}})

# Gradually increase after testing
```

___

Performance Considerations
--------------------------

1. **Header Caching**: Headers are cached in memory (TTL: 300 seconds) and Redis (TTL: 24 hours)
2. **CSP Complexity**: Complex CSP policies may impact page load time

___

Security Best Practices
------------------------

1. **Header Injection Prevention**: FastAPI Guard automatically validates all header values against injection attacks
2. **CORS Security**: Wildcard origins (`*`) are automatically blocked when credentials are enabled
3. **Thread Safety**: The SecurityHeadersManager uses thread-safe patterns for production environments
4. **Cache Security**: Secure cache key generation prevents cache poisoning attacks
5. **Input Validation**: All header values are sanitized for newlines, control characters, and excessive length
6. **Start Restrictive**: Begin with strict policies and relax as needed
7. **Monitor Violations**: Set up CSP reporting and monitoring
8. **Test Thoroughly**: Test header changes before production deployment
9. **Use HTTPS**: Many security headers require HTTPS to be effective

___

Tools and Resources
-------------------

Online Tools
------------

- [Security Headers Scanner](https://securityheaders.com)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com)
- [Mozilla Observatory](https://observatory.mozilla.org)

Browser Extensions
------------------

- CSP Evaluator Extension
- Security Headers Extension

References
----------

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN Web Docs: HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [Content Security Policy Reference](https://content-security-policy.com/)

___

Next Steps
----------

- [API Reference](../../api/security-headers.md) - Detailed API documentation
- [Configuration](../configuration/security-config.md) - Complete configuration options
- [Security Middleware](../../api/security-middleware.md) - Middleware integration
