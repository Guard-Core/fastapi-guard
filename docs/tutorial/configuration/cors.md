---

title: CORS Configuration - FastAPI Guard
description: Learn how to configure Cross-Origin Resource Sharing (CORS) settings in FastAPI Guard for secure API access
keywords: fastapi cors, cors configuration, api security, cross origin resource sharing
---

CORS Configuration
==================

FastAPI Guard provides comprehensive CORS (Cross-Origin Resource Sharing) configuration options. Set `enable_cors=True` on `SecurityConfig` and the middleware activates CORS automatically - no separate setup call is required.

___

Basic CORS Setup
-----------------

Enable CORS with default settings:

```python
config = SecurityConfig(enable_cors=True, cors_allow_origins=["*"])
app.add_middleware(SecurityMiddleware, config=config)
```

___

Advanced Configuration
----------------------

Configure specific CORS settings:

```python
config = SecurityConfig(
    enable_cors=True,
    cors_allow_origins=["https://example.com", "https://api.example.com"],
    cors_allow_methods=["GET", "POST", "PUT", "DELETE"],
    cors_allow_headers=["*"],
    cors_allow_credentials=True,
    cors_expose_headers=["X-Custom-Header"],
    cors_max_age=600,
)
app.add_middleware(SecurityMiddleware, config=config)
```

___

Origin Patterns
---------------

Use patterns to match multiple origins:

```python
config = SecurityConfig(
    enable_cors=True,
    cors_allow_origins=["https://*.example.com", "https://*.api.example.com"],
)
app.add_middleware(SecurityMiddleware, config=config)
```

___

Credentials Support
-------------------

Enable credentials support for authenticated requests:

```python
config = SecurityConfig(
    enable_cors=True,
    cors_allow_credentials=True,
    cors_allow_origins=[
        "https://app.example.com"  # Must be specific origin when using credentials
    ],
)
app.add_middleware(SecurityMiddleware, config=config)
```

___

Custom Headers
--------------

Configure custom headers for CORS:

```python
config = SecurityConfig(
    enable_cors=True,
    cors_allow_headers=["Authorization", "Content-Type", "X-Custom-Header"],
    cors_expose_headers=["X-Custom-Response-Header"],
)
app.add_middleware(SecurityMiddleware, config=config)
```
