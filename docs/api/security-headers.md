---

title: Security Headers Manager - FastAPI Guard
description: Comprehensive HTTP security header management following OWASP best practices
keywords: security headers, CSP, HSTS, X-Frame-Options, OWASP headers

---

Security Headers Manager
========================

The Security Headers Manager provides comprehensive HTTP security header management following OWASP best practices.

___

Overview
--------

The `SecurityHeadersManager` is a singleton class that manages security headers for HTTP responses, including Content Security Policy (CSP), HTTP Strict Transport Security (HSTS), and other essential security headers.

___

Class Reference
---------------

SecurityHeadersManager
----------------------

```python
from guard import SecurityHeadersManager

security_headers_manager = SecurityHeadersManager()
```

Methods
-------

configure
---------

Configure security headers settings.

```python
security_headers_manager.configure(
    enabled=True,
    csp={
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://trusted.cdn.com"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:", "https:"],
        "font-src": ["'self'", "https://fonts.gstatic.com"],
        "connect-src": ["'self'"],
        "frame-ancestors": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
    },
    hsts_max_age=31536000,  # 1 year
    hsts_include_subdomains=True,
    hsts_preload=False,
    frame_options="SAMEORIGIN",
    content_type_options="nosniff",
    xss_protection="0",
    referrer_policy="strict-origin-when-cross-origin",
    permissions_policy="geolocation=(), microphone=(), camera=()",
    custom_headers={"X-Custom-Header": "CustomValue"},
    cors_origins=["https://app.example.com"],
    cors_allow_credentials=True,
    cors_allow_methods=["GET", "POST"],
    cors_allow_headers=["*"],
    override_apps=True,  # also set these keys on every guarded app
)
```

**Parameters:**

- `enabled` (bool): Enable/disable security headers. Default: `True`
- `csp` (dict[str, list[str]] | None): Content Security Policy directives
- `hsts_max_age` (int | None): HSTS max-age in seconds (e.g., 31536000 for 1 year)
- `hsts_include_subdomains` (bool): Include subdomains in HSTS. Default: `True`
- `hsts_preload` (bool): Enable HSTS preload. Default: `False`
- `frame_options` (str | None): X-Frame-Options value (`DENY`, `SAMEORIGIN`)
- `content_type_options` (str | None): X-Content-Type-Options value
- `xss_protection` (str | None): X-XSS-Protection value
- `referrer_policy` (str | None): Referrer-Policy value
- `permissions_policy` (str | None): Permissions-Policy value
- `custom_headers` (dict[str, str] | None): Additional custom security headers
- `cors_origins` (list[str] | None): Allowed CORS origins
- `cors_allow_credentials` (bool): Allow credentials in CORS. Default: `False`
- `cors_allow_methods` (list[str] | None): Allowed CORS methods
- `cors_allow_headers` (list[str] | None): Allowed CORS headers
- `override_apps` (bool): `True` also sets the keys you pass on every guarded app in the process (see below). Default: `False`: only the manager's own headers change and no app is affected

Global `configure()` and the override
-------------------------------------

`configure()` on the global manager sets exactly what you pass. **Without `override_apps=True` it changes only the manager's own headers and does not reach any guarded app.** The middleware itself calls it at startup with every key from its config, and that call changes nothing for the apps.

- **The manager's own headers** keep the full replace: what the call does not pass is absent on the manager.
- **Every guarded app** (only with `override_apps=True`): the keys you pass override the `security_headers` config of every guarded app in the process from the next response on, for paths already served and for paths never served. Keys you do not pass are not overridden, each app keeps its own value for them. `None` switches that header off for every app, `hsts_max_age`, `hsts_include_subdomains` and `hsts_preload` merge over each app's `hsts` one by one, and a passed `enabled` wins in both directions (`enabled=True` switches on an app whose own `security_headers` is off, `enabled=False` switches every app off).
- **Clearing**: `configure(override_apps=True)` with nothing else clears the override. `await security_headers_manager.reset()` clears the manager and the override, in the process and in Redis. Writing `security_headers_manager.enabled` is never an override.
- **CORS keys** (only with `override_apps=True`): `enable_cors`, `cors_origins`, `cors_allow_credentials`, `cors_allow_methods`, `cors_allow_headers`, `cors_max_age` and `cors_expose_headers` join the override and follow the same rule: a call sets exactly what it passes, and a call that passes only CORS keys is recorded. The values are validated in `configure()` (lists of strings, bools, a non-negative integer for `cors_max_age`) and a bad value raises `ValueError`. A merge that would give wildcard origins together with credentials is refused: the app keeps its own CORS and the engine logs a WARNING and sends an event. An app built with `enable_cors=False` gets CORS only when the call passes `enable_cors=True` (a WARNING per app), and the engine then answers its preflight requests in the pipeline, after the ban and IP checks and before rate limiting. A passed `enable_cors=False` stops the CORS answers of every app. The headers `enabled` flag never governs CORS. A merge that widens the app's CORS logs a WARNING once per app and override version, a merge that narrows it logs INFO. With Redis, the CORS keys travel with the rest of the override to the other workers with the same startup config.
- **Never silent**: every call with the flag that changes the override logs one line and sends the security headers event. A call that drops keys from an active override (a clearing call included) logs a WARNING that names the dropped keys, and the event lists them. Header values in the log line and the event are redacted (a custom `X-Auth-Token` value never appears).

```python
from guard import security_headers_manager

security_headers_manager.configure(
    csp={"default-src": ["'self'", "https://cdn.example"]},
    override_apps=True,
)  # every app: this CSP
security_headers_manager.configure(
    frame_options="DENY", override_apps=True
)  # drops csp from the override: WARNING, apps use their own CSP again
security_headers_manager.configure(
    csp={"default-src": ["'none'"]}
)  # no flag: the manager only, no app changes
await security_headers_manager.reset()  # clears the override
```

With Redis on, each app saves the override with no TTL under `{redis_prefix}security_headers:override:{hash}`, where `hash` is the hash of the startup config the app runs, and each worker pulls it at most once every 5 seconds, so a call in one worker reaches the others within about 5 seconds. A worker started with another config ignores it, and a Redis error keeps the last applied override (retried after 5 seconds, whatever `redis_fail_open` says). Two services that share a `redis_prefix` and run an identical config share the override: give each service its own prefix.

get_headers
-----------

Get security headers for a response.

```python
headers = await security_headers_manager.get_headers(request_path="/api/endpoint")
```

**Parameters:**

- `request_path` (str | None): Optional request path for path-specific headers

**Returns:**

- `dict[str, str]`: Dictionary of security headers

get_cors_headers
----------------

Get CORS headers if origin is allowed.

```python
cors_headers = await security_headers_manager.get_cors_headers(
    origin="https://app.example.com"
)
```

**Parameters:**

- `origin` (str): Request origin

**Returns:**

- `dict[str, str]`: Dictionary of CORS headers

validate_csp_report
-------------------

Validate and process CSP violation reports.

```python
is_valid = await security_headers_manager.validate_csp_report(
    report={
        "csp-report": {
            "document-uri": "https://example.com/page",
            "violated-directive": "script-src",
            "blocked-uri": "https://evil.com/script.js",
            "source-file": "https://example.com/app.js",
            "line-number": 10,
        }
    }
)
```

**Parameters:**

- `report` (dict[str, Any]): CSP violation report

**Returns:**

- `bool`: True if report is valid

initialize_redis
----------------

Initialize Redis connection for caching header configurations.

```python
await security_headers_manager.initialize_redis(redis_handler)
```

**Parameters:**

- `redis_handler` (Any): Redis handler instance

initialize_agent
----------------

Initialize agent integration for security event tracking.

```python
await security_headers_manager.initialize_agent(agent_handler)
```

**Parameters:**

- `agent_handler` (Any): Agent handler instance

reset
-----

Reset all security headers configuration.

```python
await security_headers_manager.reset()
```

___

Default Headers
---------------

The following headers are configured by default:

| Header | Default Value | Description |
|--------|--------------|-------------|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME type sniffing |
| `X-Frame-Options` | `SAMEORIGIN` | Prevents clickjacking attacks |
| `X-XSS-Protection` | `0` | Turns the legacy browser XSS filter off |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controls referrer information |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | Restricts browser features |
| `X-Permitted-Cross-Domain-Policies` | `none` | Restricts Adobe Flash cross-domain access |
| `X-Download-Options` | `noopen` | Prevents file download execution in IE |
| `Cross-Origin-Embedder-Policy` | not sent (opt in with `cross_origin_embedder_policy`) | Controls cross-origin resource embedding |
| `Cross-Origin-Opener-Policy` | `same-origin` | Controls cross-origin window interactions |
| `Cross-Origin-Resource-Policy` | `same-site` | Controls cross-origin resource access |

___

Content Security Policy (CSP)
------------------------------

CSP helps prevent XSS attacks by specifying which sources are allowed for various content types.

Common CSP Directives
---------------------

- `default-src`: Default policy for all resource types
- `script-src`: Valid sources for JavaScript
- `style-src`: Valid sources for stylesheets
- `img-src`: Valid sources for images
- `font-src`: Valid sources for fonts
- `connect-src`: Valid sources for fetch, XMLHttpRequest, WebSocket
- `frame-src`: Valid sources for frames
- `frame-ancestors`: Valid parents that may embed a page
- `base-uri`: Restricts URLs for `<base>` element
- `form-action`: Valid endpoints for form submissions
- `report-uri`: URL to send CSP violation reports

CSP Source Values
-----------------

- `'self'`: Same origin
- `'none'`: No sources allowed
- `'unsafe-inline'`: Allow inline scripts/styles (use with caution)
- `'unsafe-eval'`: Allow eval() (use with caution)
- `https:`: Any HTTPS source
- `data:`: Data URIs
- Specific domains: `https://trusted.cdn.com`

___

HTTP Strict Transport Security (HSTS)
---------------------------------------

HSTS forces browsers to use HTTPS connections.

HSTS Configuration
------------------

```python
hsts_config = {
    "max_age": 31536000,  # 1 year in seconds
    "include_subdomains": True,  # Apply to all subdomains
    "preload": False,  # Submit to HSTS preload list
}
```

HSTS Preload Requirements
-------------------------

To enable HSTS preload:

1. Serve a valid certificate
2. Redirect all HTTP to HTTPS
3. Serve all subdomains over HTTPS
4. Set `max_age` to at least 31536000 (1 year)
5. Include `includeSubDomains`
6. Include `preload`

___

CORS Integration
----------------

The Security Headers Manager integrates with CORS configuration:

```python
# CORS headers are automatically added when:
# 1. An origin header is present in the request
# 2. The origin is in the allowed list
cors_config = {
    "origins": ["https://app.example.com", "https://admin.example.com"],
    "allow_credentials": True,
    "allow_methods": ["GET", "POST", "PUT", "DELETE"],
    "allow_headers": ["*"],
}
```

___

Redis Caching
-------------

Header configurations are cached in Redis for performance:

- CSP configuration: Cached with key `security_headers:csp_config`
- HSTS configuration: Cached with key `security_headers:hsts_config`
- Custom headers: Cached with key `security_headers:custom_headers`
- TTL: 86400 seconds (24 hours)

___

Agent Integration
-----------------

When agent is configured, the following events are sent:

- `security_headers_applied`: When headers are added to a response
- `csp_violation`: When a CSP violation report is received

___

Example Usage
-------------

Basic Configuration
-------------------

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard import SecurityConfig

app = FastAPI()

config = SecurityConfig(
    security_headers={
        "enabled": True,
        "hsts": {"max_age": 31536000, "include_subdomains": True, "preload": False},
        "frame_options": "DENY",
        "content_type_options": "nosniff",
        "xss_protection": "0",
        "referrer_policy": "no-referrer",
        "permissions_policy": "geolocation=(), microphone=(), camera=()",
    }
)

app.add_middleware(SecurityMiddleware, config=config)
```

Advanced CSP Configuration
--------------------------

```python
config = SecurityConfig(
    security_headers={
        "enabled": True,
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            "img-src": ["'self'", "data:", "https:"],
            "font-src": ["'self'", "https://fonts.gstatic.com"],
            "connect-src": ["'self'", "https://api.example.com"],
            "frame-ancestors": ["'none'"],
            "base-uri": ["'self'"],
            "form-action": ["'self'"],
            "report-uri": ["/api/csp-report"],
        },
    }
)
```

CSP Report Endpoint
-------------------

```python
from fastapi import Request


@app.post("/api/csp-report")
async def handle_csp_report(request: Request):
    report = await request.json()
    is_valid = await security_headers_manager.validate_csp_report(report)

    if is_valid:
        # Report is logged automatically by the manager
        return {"status": "received"}

    return {"status": "invalid"}
```

Disabling Specific Headers
---------------------------

```python
config = SecurityConfig(
    security_headers={
        "enabled": True,
        "frame_options": None,  # Disable X-Frame-Options
        "permissions_policy": None,  # Disable Permissions-Policy
        # Other headers remain at defaults
    }
)
```

___

Best Practices
--------------

1. **Gradual HSTS Rollout**: Start with a small `max_age` and gradually increase
2. **Test Thoroughly**: Security headers can break functionality if too restrictive
3. **Monitor CSP Reports**: Set up monitoring for CSP violations
4. **Use HTTPS**: Many security headers require HTTPS to be effective
5. **Browser Compatibility**: Check browser support for specific headers

___

Security Considerations
------------------------

- **Header Injection Prevention**: All header values are validated against injection attacks, newlines, and excessive length
- **CORS Security**: Wildcard origins (`*`) cannot be used with credentials: `SecurityConfig` refuses the combination when it is built (`fail_on_misconfiguration=True`), and with it `False` logs one WARNING and drops credentials
- **Thread Safety**: SecurityHeadersManager uses thread-safe singleton pattern with double-checked locking
- **Cache Security**: Cache keys are generated using SHA256 hashing to prevent cache poisoning attacks
- **CSP Validation**: Unsafe directives like `'unsafe-inline'` and `'unsafe-eval'` trigger security warnings
- **HSTS Preload**: Strict validation ensures preload requirements (max_age ≥ 1 year, includeSubDomains)
- **CSP Bypasses**: Be aware of potential CSP bypasses with `'unsafe-inline'` and `'unsafe-eval'`
- **HSTS Commitment**: Once HSTS is enabled with a long `max_age`, it cannot be easily undone
- **Frame Options**: Consider using CSP's `frame-ancestors` instead of `X-Frame-Options`
- **Legacy Headers**: Some headers like `X-XSS-Protection` are being phased out in modern browsers
- **Performance**: Complex CSP policies can impact page load performance

___

See Also
--------

- [HTTP Security Headers Tutorial](../tutorial/security/http-security-headers.md) - Comprehensive guide
- [Security Configuration](../tutorial/configuration/security-config.md) - Configuration options
- [Security Middleware](security-middleware.md) - Middleware integration
