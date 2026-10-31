---

title: IP Geolocation - FastAPI Guard
description: Configure country-based IP filtering and geolocation features using IPInfo's database in FastAPI Guard
keywords: ip geolocation, country blocking, ipinfo integration, location filtering
---

IP Geolocation
==============

FastAPI Guard accepts an arbitrary class that implements geolocation and country-based filtering. All it needs is to implement the following protocol:

```python
class GeoIPHandler(Protocol):
    """
    Protocol for geographical IP handler.
    """

    @property
    def is_initialized(self) -> bool: ...

    async def initialize(self) -> None: ...

    async def initialize_redis(self, redis_handler: "RedisHandlerProtocol") -> None: ...

    async def initialize_agent(self, agent_handler: "AgentHandlerProtocol") -> None: ...

    def get_country(self, ip: str) -> str | None: ...

    async def refresh(self) -> None: ...

    def close(self) -> None: ...
```

It provides an implementation that uses the [ipinfo.io](https://ipinfo.io/signup) service:

```python
from guard import IPInfoManager
```

The geolocation handler is only initialized and used when country filtering is configured, improving performance for applications that don't need these features.

___

Setup
-----

Option 1: Using the built-in IPInfoHandler
-------------------------------------------

1. Get your IPInfo token from [ipinfo.io](https://ipinfo.io/signup)
2. Configure geolocation in your app:

```python
config = SecurityConfig(
    geo_ip_handler=IPInfoManager(
        "your_ipinfo_token_here",
        db_path=Path("custom/ipinfo.db"),  # Optional custom database path
    ),  # NOTE: Required when using country filtering
    blocked_countries=["CN", "RU"],  # Block specific countries
    block_cloud_providers={"AWS", "GCP"},  # Provider names, matched case-insensitively
)
```

Use `whitelist_countries=["US", "CA"]` instead of `blocked_countries` to allow only those countries. A non-empty `whitelist_countries` is restrictive, so `blocked_countries` has no effect while it is set and guard-core warns about the combination.

Option 2: Providing a custom geographical IP handler
----------------------------------------------------

```python
class CustomGeoIPHandler:
    """
    Your custom class.
    """

    @property
    def is_initialized(self) -> bool:
        # your implementation
        ...

    async def initialize(self) -> None:
        # your implementation
        ...

    async def initialize_redis(self, redis_handler: "RedisHandlerProtocol") -> None:
        # your implementation
        ...

    async def initialize_agent(self, agent_handler: "AgentHandlerProtocol") -> None:
        # your implementation
        ...

    def get_country(self, ip: str) -> str | None:
        # your implementation
        ...

    async def refresh(self) -> None:
        # your implementation
        ...

    def close(self) -> None:
        # your implementation
        ...


config = SecurityConfig(
    geo_ip_handler=CustomGeoIPHandler(),
    blocked_countries=["CN", "RU"],  # Block specific countries
    block_cloud_providers={"AWS", "GCP"},  # Provider names, matched case-insensitively
)
```

___

Country Blocking
----------------

Block requests from specific countries using ISO 3166-1 alpha-2 country codes:

```python
config = SecurityConfig(
    geo_ip_handler=IPInfoManager(
        "your_ipinfo_token_here"
    ),  # NOTE: Required when using country filtering
    blocked_countries=[
        "CN",  # China
        "RU",  # Russia
        "IR",  # Iran
        "KP",  # North Korea
    ],
)
```

___

Country Whitelisting
--------------------

Only allow requests from specific countries:

```python
config = SecurityConfig(
    geo_ip_handler=IPInfoManager(
        "your_ipinfo_token_here"
    ),  # NOTE: Required when using country filtering
    whitelist_countries=[
        "US",  # United States
        "CA",  # Canada
        "GB",  # United Kingdom
        "AU",  # Australia
    ],
)
```

___

Custom Geolocation Logic
------------------------

You can also use the `IPInfoManager` directly for custom geolocation logic:

```python
from guard import IPInfoManager

ipinfo_db = IPInfoManager(
    token="your_ipinfo_token_here"
)  # NOTE: Required when using custom geolocation
await ipinfo_db.initialize()


@app.get("/country/{ip}")
async def get_ip_country(ip: str):
    country = ipinfo_db.get_country(ip)
    return {"ip": ip, "country": country}
```
