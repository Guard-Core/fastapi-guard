---

title: CloudManager API - FastAPI Guard
description: API reference for managing and detecting IP addresses from major cloud providers
keywords: cloud ip detection, aws ip ranges, gcp ip ranges, azure ip ranges
---

CloudManager
============

The `CloudManager` class manages detection of IP addresses from major cloud providers. It uses a singleton pattern to ensure only one instance exists throughout the application.

___

Class Definition
----------------

```python
class CloudManager:
    _instance = None
    ip_ranges: dict[str, set[ipaddress.IPv4Network | ipaddress.IPv6Network]]
    redis_handler: Any = None
    agent_handler: Any = None
    logger: logging.Logger
    last_updated: dict[str, datetime | None]

    def __new__(cls: type["CloudManager"]) -> "CloudManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.ip_ranges = {
                "AWS": set(),
                "GCP": set(),
                "Azure": set(),
                "DigitalOcean": set(),
                "Linode": set(),
                "Vultr": set(),
            }
            cls._instance.last_updated = {provider: None for provider in _ALL_PROVIDERS}
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
            cls._instance.logger = logging.getLogger("guard_core.handlers.cloud")
        return cls._instance
```

___

Redis Integration
-----------------

When Redis is enabled, CloudManager automatically:

- Caches cloud IP ranges in Redis with configurable TTL (default: 1 hour, set via `cloud_ip_refresh_interval`)
- Uses cached ranges if available
- Synchronizes ranges across instances

___

Methods
-------

refresh
-------

```python
async def refresh(self, providers: set[str] = _ALL_PROVIDERS) -> None:
    """
    Refresh of IP ranges from cloud providers.
    Only available when Redis is not enabled; raises RuntimeError
    when Redis is configured (use refresh_async instead).
    """
```

refresh_async
-------------

```python
async def refresh_async(self, providers: set[str] = _ALL_PROVIDERS, ttl: int = 3600):
    """
    Async refresh of IP ranges with Redis caching.

    Args:
        providers: Set of provider names to refresh
        ttl: Redis cache TTL in seconds (default: 3600)
    """
```

initialize_redis
----------------

```python
async def initialize_redis(
    self, redis_handler: Any, providers: set[str] = _ALL_PROVIDERS, ttl: int = 3600
):
    """
    Initialize Redis integration and load IP ranges.

    Args:
        redis_handler: Redis handler instance
        providers: Set of provider names to load
        ttl: Redis cache TTL in seconds (default: 3600)
    """
```

_log_range_changes
------------------

```python
def _log_range_changes(
    self,
    provider: str,
    old_ranges: set[ipaddress.IPv4Network | ipaddress.IPv6Network],
    new_ranges: set[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> None:
    """
    Log additions and removals when IP ranges change for a provider.
    Called automatically during refresh operations.
    """
```

is_cloud_ip
-----------

```python
def is_cloud_ip(self, ip: str, providers: set[str]) -> bool:
    """
    Check if an IP belongs to specified cloud providers.

    Args:
        ip: IP address to check
        providers: Set of provider names ('AWS', 'GCP', 'Azure',
            'DigitalOcean', 'Linode', 'Vultr')
    """
```

___

Usage Example
-------------

```python
from guard import cloud_handler

# The singleton instance is already created

# Check if IP is from AWS
is_aws = cloud_handler.is_cloud_ip("54.239.28.85", {"AWS"})

# Check multiple providers
is_cloud = cloud_handler.is_cloud_ip("35.186.224.25", {"AWS", "GCP", "Azure"})

# Refresh IP ranges manually if needed
await cloud_handler.refresh()  # Raises RuntimeError when Redis is enabled
await cloud_handler.refresh_async()  # Asynchronous with Redis

# Check when a provider was last refreshed
aws_updated = cloud_handler.last_updated["AWS"]
if aws_updated:
    print(f"AWS ranges last refreshed: {aws_updated.isoformat()}")
```

!!! note "Per-app accessor: `cloud_handler_for`"
    `cloud_handler` is the module-level singleton. It serves the first app built in the process, and any later app that shares its Redis prefix or has no Redis. An app on its own Redis prefix gets a separate cloud manager, and the engine resolves the manager of the app in flight with `cloud_handler_for(config)` on every request. Use the singleton for a single-app process, or to read the shared provider ranges. When a process builds more than one config (an app factory, a reload, tests), call `cloud_handler_for(config)` with the config of the app you mean, so you never talk to another app's manager. It is public, is not re-exported by this package, and is imported from `guard_core.handlers.cloud_handler`: `from guard_core.handlers.cloud_handler import cloud_handler_for`.
