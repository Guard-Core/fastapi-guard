---

title: Advanced Customization - FastAPI Guard
description: Learn how to extend FastAPI Guard with custom protocols and handlers
keywords: custom protocols, extending fastapi guard, advanced customization
---

Advanced Customization
=======================

FastAPI Guard uses a protocol-based architecture that makes it highly extensible. This guide explains how the protocol system works and how to create custom implementations.

___

Protocol-Based Architecture
----------------------------

FastAPI Guard uses Python's Protocol system to define interfaces that components must implement. This allows you to:

1. Replace built-in handlers with custom implementations
2. Extend functionality without modifying the core library
3. Better separate concerns in your codebase

___

Why Protocols?
--------------

The protocol system solves several important problems:

1. **Avoiding dependency on third-party services**: You can replace the built-in IPInfo geo-location with your own service
2. **Preventing circular imports**: The protocols help break dependency cycles in the codebase
3. **Enabling extension points**: Clear interfaces for adding custom functionality

___

Available Protocols
-------------------

GeoIPHandler Protocol
---------------------

The `GeoIPHandler` protocol defines the interface for any geographical IP handler:

```python
@runtime_checkable
class GeoIPHandler(Protocol):
    """Protocol for geographical IP handler."""

    @property
    def is_initialized(self) -> bool: ...

    async def initialize(self) -> None: ...

    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None: ...

    def get_country(self, ip: str) -> str | None: ...
```

Method Details
--------------

- `is_initialized`: Should return whether the handler is ready to use
- `initialize()`: Should set up the handler (load databases, connect to APIs, etc.)
- `initialize_redis()`: Should store the redis handler for optional caching
- `get_country()`: Should return the ISO 3166-1 alpha-2 country code for the IP

RedisHandlerProtocol
--------------------

**IMPORTANT**: Users do NOT need to implement this protocol. It exists purely for internal use to break dependency cycles and define what the Redis handler must support for the custom GeoIP handlers.

```python
@runtime_checkable
class RedisHandlerProtocol(Protocol):
    """Protocol for Redis handlers."""

    async def get_key(self, namespace: str, key: str) -> Any: ...

    async def set_key(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool | None: ...

    def get_connection(self) -> AsyncContextManager[Redis]: ...

    async def initialize(self) -> None: ...
```

___

How Protocols Are Used
----------------------

The FastAPI Guard initialization flow works like this:

1. You create a `SecurityConfig` with your custom `geo_ip_handler`
2. You add the `SecurityMiddleware` with this config
3. When the middleware initializes, it:
   - Checks if you provided a `geo_ip_handler` that implements the protocol
   - If Redis is enabled, it passes its internal `RedisManager` to your handler
   - Your handler can use this Redis connection for caching or whatever you need

This makes your custom geo IP handler fully integrated with the middleware's Redis infrastructure.

___

Implementation Examples
-----------------------

Example: Custom Geo IP Service
-------------------------------

Here's a complete example of a custom GeoIPHandler implementation that uses a different service:

```python
from guard import GeoIPHandler, RedisHandlerProtocol


class CustomGeoIPHandler:
    """Custom handler using Custom GeoIP database"""

    def __init__(self, license_key: str, db_path: str = "CustomGeoIP.mmdb"):
        self._initialized = False
        self.license_key = license_key
        self.db_path = db_path
        self.reader = None
        self.redis = None  # Will store the FastAPI Guard's Redis handler

    @property
    def is_initialized(self) -> bool:
        return self.reader is not None

    async def initialize(self) -> None:
        """Initialize by downloading or loading the Custom GeoIP database"""
        import os
        import somelibrary

        # Check if we have a cached copy in Redis
        if self.redis:
            cached_db = await self.redis.get_key("custom", "database")
            if cached_db:
                with open(self.db_path, "wb") as f:
                    f.write(
                        cached_db
                        if isinstance(cached_db, bytes)
                        else cached_db.encode("latin-1")
                    )
                self.reader = somelibrary.Reader(self.db_path)
                self._initialized = True
                return

        # Download if needed (simplified - in a real app, use your API)
        if not os.path.exists(self.db_path):
            # Custom code to download database using license_key
            pass

        # Open the database
        if os.path.exists(self.db_path):
            self.reader = somelibrary.Reader(self.db_path)
            self._initialized = True

    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        """Store Redis handler and initialize"""
        self.redis = redis_handler  # Store the Redis handler provided by FastAPI Guard
        await self.initialize()

    def get_country(self, ip: str) -> str | None:
        """Get country code from IP using Custom GeoIP database"""
        if not self.reader:
            raise RuntimeError("Database not initialized")

        try:
            response = self.reader.country(ip)
            return response.country.iso_code
        except Exception:
            return None
```

___

Usage in Application
--------------------

```python
from fastapi import FastAPI
from guard import SecurityMiddleware, SecurityConfig
from your_custom_module import CustomGeoIPHandler

app = FastAPI()

# Use custom handler instead of default IPInfoManager
config = SecurityConfig(
    geo_ip_handler=CustomGeoIPHandler(args),
    blocked_countries=["CN", "RU"],
    # Other configuration...
)

app.add_middleware(SecurityMiddleware, config=config)
```

___

Technical Details: How Redis Integration Works
----------------------------------------------

When you create a custom GeoIPHandler:

1. FastAPI Guard's middleware will call your handler's `initialize_redis()` method
2. It passes its internal `RedisManager` to your handler
3. Your handler can store this manager and use it for caching

You don't need to:

- Create your own Redis connection
- Implement RedisHandlerProtocol
- Manage Redis connection pools

The built-in RedisManager handles all of this for you.

When a GeoIPHandler implementation receives a Redis handler in `initialize_redis()`, it can use it to:

1. Cache lookup results to improve performance
2. Store database files across application restarts
3. Share state across multiple application instances

The Redis handler provides these key methods:

```python
# Store a value with optional TTL
await redis_handler.set_key("namespace", "key", "value", ttl=3600)

# Retrieve a value
value = await redis_handler.get_key("namespace", "key")

# Use the connection directly (advanced)
async with redis_handler.get_connection() as conn:
    # Direct Redis operations
    pass
```

Remember: You don't implement the RedisHandlerProtocol yourself - FastAPI Guard provides its built-in RedisManager which meets this protocol and is automatically passed to your custom GeoIPHandler.

If you pass your own Redis handler to the engine, give it `is_connected() -> bool`; a `RedisHandlerBase` subclass inherits it from the built-in manager and overrides it only when its client lives somewhere other than `_redis`. With `redis_fail_open=True` the engine calls it after a cold-start reconnect, falls back to a `_redis` attribute when the handler has no `is_connected`, and reports a handler with neither at startup (a `ValueError` under the default `fail_on_misconfiguration=True`).
