---

title: RateLimitManager - FastAPI Guard
description: API reference for the RateLimitManager class in FastAPI Guard, handling rate limiting functionality
keywords: rate limiting, api security, fastapi, rate limit handler
---

RateLimitManager
================

The `RateLimitManager` is responsible for managing rate limiting functionality in FastAPI Guard. It supports both in-memory rate limiting using timestamp tracking and distributed rate limiting using Redis.

___

Overview
--------

Rate limiting is an essential security feature that protects your API from abuse by limiting the number of requests a client can make within a specific time window. The `RateLimitManager` implements this functionality with the following features:

- **True sliding window algorithm**: Tracks individual request timestamps rather than simple counters
- **In-memory timestamp tracking**: Uses deques for efficient, chronological storage
- **Redis-based distributed rate limiting**: Optional support for distributed environments
- **Atomic Redis operations**: Uses Lua scripts for consistent counting across instances
- **Configurable limits and windows**: Set your own thresholds and time periods
- **Singleton pattern**: Ensures consistent state across requests
- **Automatic cleanup**: Expired timestamps are automatically removed

___

Example Usage
-------------

```python
from fastapi import FastAPI
from guard import SecurityMiddleware
from guard import SecurityConfig

app = FastAPI()

# Configure rate limiting
config = SecurityConfig(
    rate_limit=100,  # Max 100 requests
    rate_limit_window=60,  # Per minute
    enable_rate_limiting=True,  # Enable rate limiting (true by default)
    enable_redis=True,  # Use Redis for distributed setup (true by default)
    redis_url="redis://localhost:6379/0",
)

# Add middleware with rate limiting
app.add_middleware(SecurityMiddleware, config=config)
```

___

Advanced Configuration
----------------------

Redis Integration
-----------------

When using Redis for distributed rate limiting, the handler creates sorted sets with the following pattern:

```text
{redis_prefix}rate_limit:rate:{client_ip}
```

Each entry in the sorted set represents a request timestamp. The keys automatically expire after twice the configured window duration.

Redis Lua Script
-----------------

The rate limiter uses a Redis Lua script for atomic operations in distributed environments:

1. Add the current timestamp to the sorted set
2. Remove timestamps outside the current window
3. Count the number of timestamps within the window
4. Set expiry for the key

This ensures that rate limiting is consistent even in high-concurrency environments.

___

Direct Access
-------------

You can also access the handler directly if needed. Pass the same config object the guarded app was built with: managers built from the same config object share one state (windows, Redis and agent handlers), so `reset()` reaches what the app counts. A different config object, even an equal one or a `model_copy()`, has its own state, and `reset()` on a state no guarded app was built with logs a warning and clears nothing the app uses.

```python
from guard import rate_limit_handler

# Pass the config object the app was built with: managers built from the
# same config object share one state, so this reaches the app's limiter
handler = rate_limit_handler(config)

# Reset all rate limits
await handler.reset()
```

___

Performance Considerations
--------------------------

- **In-memory rate limiting** has lower latency but doesn't work in distributed environments
- **Redis-based rate limiting** works across multiple instances but adds network overhead
- The sliding window algorithm ensures accurate rate limiting without traffic spikes at window boundaries
- Automatic cleanup of old timestamps prevents memory leaks

___

See Also
--------

- [Rate Limiting Tutorial](../tutorial/ip-management/rate-limiter.md)
- [Redis Integration](../tutorial/redis-integration/caching.md)
- [SecurityMiddleware](./security-middleware.md)
