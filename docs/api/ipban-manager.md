---

title: IPBanManager API - FastAPI Guard
description: API reference for FastAPI Guard's IP banning system, including automatic and manual IP management
keywords: ip ban api, ban management, ip blocking api, security api
---

IPBanManager
============

The `IPBanManager` class handles temporary IP bans in your FastAPI application.

___

Overview
--------

```python
from guard import IPBanManager

ip_ban_manager = IPBanManager()
```

The `IPBanManager` uses an in-memory cache to track banned IPs and their ban durations.

___

Distributed Banning
-------------------

When Redis is enabled:

- Bans are shared across instances
- Ban expiration is handled automatically
- Supports atomic ban operations

```python
# Cluster-wide ban
await ip_ban_manager.ban_ip("192.168.1.1", 3600)

# Check ban status across cluster
is_banned = await ip_ban_manager.is_ip_banned("192.168.1.1")
```

___

Methods
-------

ban_ip
------

Ban an IP address for a specified duration.

```python
async def ban_ip(ip: str, duration: int, reason: str = "threshold_exceeded") -> None
```

**Parameters**:

- `ip`: The IP address to ban
- `duration`: Ban duration in seconds
- `reason`: Ban reason used as the `SecurityEvent` reason when an agent handler is configured (defaults to `"threshold_exceeded"`)

**Example**:

```python
await ip_ban_manager.ban_ip("192.168.1.1", 3600)  # Ban for 1 hour
```

is_ip_banned
------------

Check if an IP address is currently banned.

```python
async def is_ip_banned(ip: str) -> bool
```

**Parameters**:

- `ip`: The IP address to check

**Returns**:

- `bool`: True if the IP is banned, False otherwise

**Example**:

```python
is_banned = await ip_ban_manager.is_ip_banned("192.168.1.1")
```

reset
-----

Reset all banned IPs and every auto-ban strike (the rate-limit and the detection strikes, in memory and in Redis, across every worker that shares the Redis prefix). `unban_ip(ip)` clears that IP's strikes too, and `unban_inside(entries)` clears the strikes of exactly the addresses it removed, so a lifted ban is not reinstated by strikes from before it. Redis is walked with `SCAN` and cleared with `UNLINK`, never `KEYS`.

```python
async def reset() -> None
```

**Example**:

```python
await ip_ban_manager.reset()
```

___

Usage with SecurityMiddleware
-----------------------------

The `IPBanManager` is automatically integrated when you use the `SecurityMiddleware`:

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard import SecurityConfig

app = FastAPI()

config = SecurityConfig(
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    auto_ban_duration=3600,  # Ban for 1 hour
)

app.add_middleware(SecurityMiddleware, config=config)
```
