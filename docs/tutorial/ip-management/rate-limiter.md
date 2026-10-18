---

title: Rate Limiting - FastAPI Guard
description: Learn how to implement rate limiting in your FastAPI application using FastAPI Guard
keywords: rate limiting, api security, ddos protection, request throttling, fastapi
---

Rate Limiting
=============

Rate limiting is a crucial security feature that protects your API from abuse, DoS attacks, and excessive usage. FastAPI Guard provides a robust rate limiting system through the dedicated `RateLimitManager` class.

___

Basic Configuration
-------------------

To enable rate limiting, configure the following parameters in your `SecurityConfig`:

```python
from fastapi import FastAPI
from guard import SecurityMiddleware
from guard import SecurityConfig

app = FastAPI()

config = SecurityConfig(
    # NOTE: enable_rate_limiting is not required, it's enabled by default
    rate_limit=100,  # Maximum number of requests allowed
    rate_limit_window=60,  # Time window in seconds
    # ... other configuration options ...
)

app.add_middleware(SecurityMiddleware, config=config)
```

___

How It Works
------------

FastAPI Guard implements a sliding window rate limiting algorithm:

1. Each client request is tracked using a timestamp
2. Only requests within the current time window (last `rate_limit_window` seconds) are counted
3. When a new request arrives, timestamps older than the window are automatically discarded
4. If the count of valid timestamps exceeds `rate_limit`, the request is rejected with a 429 status
5. This ensures precise rate limiting without artificial time boundaries

The sliding window approach offers several advantages over fixed windows:

- No traffic spikes at window boundaries
- More consistent load on your API
- Fair treatment of users across time periods
- More accurate request counting

___

In-Memory vs. Redis Rate Limiting
---------------------------------

FastAPI Guard supports two rate limiting storage backends:

In-Memory Rate Limiting
-----------------------

By default, rate limiting uses an in-memory deque for tracking request timestamps:

```python
config = SecurityConfig(
    # Rate limit is enabled by default
    rate_limit=100,
    rate_limit_window=60,
    enable_redis=False,
)
```

**Pros:**

- Simple setup (no external dependencies)
- Fast performance
- Automatic cleanup of old timestamps
- True sliding window algorithm

**Cons:**

- Doesn't work across multiple application instances
- Lost on application restart
- Consumes application memory

Redis-Based Rate Limiting
-------------------------

For distributed environments, enable Redis-based rate limiting:

```python
config = SecurityConfig(
    # NOTE: enable_rate_limiting is not required, it's enabled by default
    rate_limit=100,
    rate_limit_window=60,
    redis_url="redis://localhost:6379/0",
    redis_prefix="myapp:",  # Optional prefix for Redis keys (override default)
)
```

**Pros:**

- Works across multiple application instances
- Persists through application restarts
- Uses atomic Lua scripts for reliable concurrency handling
- Consistent rate limiting across distributed systems

**Cons:**

- Requires a Redis server
- Slightly higher latency due to network calls
- Additional infrastructure dependency

___

Custom Response Messages
------------------------

You can customize the rate limit exceeded message:

```python
config = SecurityConfig(
    # NOTE: enable_rate_limiting is not required, it's enabled by default
    rate_limit=100,
    rate_limit_window=60,
    custom_error_responses={429: "Rate limit exceeded. Please try again later."},
)
```

___

Advanced Usage
--------------

Accessing the Rate Limiter Directly
------------------------------------

For advanced use cases, you can access the rate limiter directly:

```python
from guard import rate_limit_handler


async def some_route():
    # Get a reference to the handler (pass the config object the app was built with)
    handler = rate_limit_handler(config)

    # Reset rate limits (e.g., for a premium user)
    await handler.reset()
```

Resetting Rate Limits
---------------------

You might want to reset rate limits in certain scenarios:

```python
from guard import rate_limit_handler


async def reset_rate_limits_for_user(user_id: str):
    handler = rate_limit_handler(config)

    # Clear all rate limits (use with caution)
    await handler.reset()
```

Implementation Details
----------------------

Managers built from the same config object share one state, which keeps the counts consistent across requests (a different config object has its own state). It uses:

- TTLCache for in-memory storage with automatic expiration
- Redis increments with TTL for distributed storage
- Efficient counter storage to minimize memory footprint

___

Best Practices
--------------

1. **Set reasonable limits**: Consider your API's typical usage patterns
2. **Use Redis in production**: For reliability in distributed environments
3. **Implement graduated limits**: Consider different limits for different API endpoints
4. **Inform clients**: Return appropriate headers with rate limit information
5. **Monitor usage patterns**: Keep an eye on rate limit hits to adjust as needed

___

See Also
--------

- [RateLimitManager API Reference](../../api/ratelimit-manager.md)
- [Redis Integration](../redis-integration/caching.md)
- [Security Middleware](../../api/security-middleware.md)
