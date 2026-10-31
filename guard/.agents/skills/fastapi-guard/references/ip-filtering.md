# IP Filtering

## whitelist vs blacklist

`whitelist` (`list[str] | None`, default `None`): when non-empty, only listed IPs/CIDRs pass the global IP check. It is restrictive.

`blacklist` (`list[str]`, default `[]`): blocked IPs/CIDRs. Enforced ahead of country and cloud-provider checks.

An explicit whitelist match overrides the blacklist. Dynamic IP bans (from `auto_ban_threshold`) still apply to both lists.

```python
from guard import SecurityConfig

config = SecurityConfig(
    whitelist=["10.0.0.0/8", "192.168.1.1"],
    blacklist=["203.0.113.0/24"],
)
```

## IP banning

```python
config = SecurityConfig(
    enable_ip_banning=True,
    auto_ban_threshold=5,
    auto_ban_duration=86400,
)
```

`auto_ban_threshold` is the suspicious-event count within the tracking window that triggers an automatic ban. `auto_ban_duration` is the ban TTL in seconds. `category_thresholds` overrides the threshold/duration per suspicious category; unlisted categories fall back to the global values.

## Country rules

```python
from guard import IPInfoManager

config = SecurityConfig(
    blocked_countries={"CN", "RU"},
    geo_ip_handler=IPInfoManager("your_token_here"),
)
```

Use `whitelist_countries={"US", "CA"}` instead to let only the listed countries through; when both are set, `blocked_countries` is ignored and a warning says so.

Country rules require a geo IP handler. Set `geo_ip_handler` when `whitelist_countries` or `blocked_countries` is configured, either to a custom `GeoIPHandler` implementation or to `IPInfoManager(token=...)` directly. The `ipinfo_token` and `ipinfo_db_path` config fields are deprecated (they exist only so `geo_ip_handler` can be auto-constructed as an `IPInfoManager` when omitted); pass `geo_ip_handler=IPInfoManager(...)` explicitly instead of those two fields.

If country rules are set but no handler is available, the middleware raises a configuration error at construction time.

## Cloud providers

```python
config = SecurityConfig(
    block_cloud_providers={"AWS", "GCP", "Azure"},
)
```

Blocks requests originating from the listed cloud-provider IP ranges. Cloud-provider checks run after the explicit blacklist and are overridden by an explicit whitelist match.

## Redis-backed state

Redis (`enable_redis=True`, or any Redis connection field such as `redis_url` set explicitly; off otherwise since guard-core 5.0.0) holds distributed ban state and rate-limit counters so limits hold across multiple workers. `redis_url`, `redis_prefix`, `redis_socket_connect_timeout`, `redis_socket_timeout`, `redis_health_check_interval`, `redis_max_connections`, and `redis_retries` tune the pool. Keep the socket timeouts low, because every blocked Redis call blocks a request.
