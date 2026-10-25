---

title: Cloud Provider IP Blocking - FastAPI Guard
description: Block requests from major cloud providers like AWS, GCP, and Azure using FastAPI Guard's IP management
keywords: cloud ip blocking, aws blocking, gcp blocking, azure blocking, cloud security
---

Cloud Provider IP Blocking
===========================

FastAPI Guard can automatically detect and block requests from major cloud providers. The IP ranges for these providers are only loaded when cloud blocking is enabled, improving startup performance.

___

Supported Providers
-------------------

Currently supported cloud providers:

- Amazon Web Services (AWS)
- Google Cloud Platform (GCP)
- Microsoft Azure

___

Basic Configuration
-------------------

Enable cloud provider IP blocking:

```python
config = SecurityConfig(block_cloud_providers={"AWS", "GCP", "Azure"})
```

___

Selective Blocking
------------------

Block specific providers:

```python
config = SecurityConfig(
    block_cloud_providers={"AWS"}  # Only block AWS IPs
)
```

___

IP Range Updates
----------------

Cloud IP ranges are refreshed automatically at a configurable interval (default: 1 hour). You can adjust the refresh interval:

```python
config = SecurityConfig(
    block_cloud_providers={"AWS", "GCP", "Azure"},
    cloud_ip_refresh_interval=1800,  # Refresh every 30 minutes
)
```

Valid range: 60 to 86400 seconds (1 minute to 24 hours).

When IP ranges are refreshed, changes are logged automatically:

```text
Cloud IP range update for AWS: +12 added, -3 removed
```

You can also manually trigger a refresh:

```python
from guard_core.handlers.cloud_handler import cloud_handler_for

# The module-level objects are the default app's. Take the ones of the app
# you act on with the config that app was built with.
clouds = cloud_handler_for(security_config)

clouds.refresh()
```

___

Provider Status
---------------

Track when each provider's IP ranges were last refreshed:

```python
from guard_core.handlers.cloud_handler import cloud_handler_for

# The module-level objects are the default app's. Take the ones of the app
# you act on with the config that app was built with.
clouds = cloud_handler_for(security_config)

for provider in ("AWS", "GCP", "Azure"):
    updated = clouds.last_updated[provider]
    if updated:
        print(f"{provider}: last updated {updated.isoformat()}")
    else:
        print(f"{provider}: not yet loaded")
```

___

Custom IP Checking
-------------------

Check if an IP belongs to a cloud provider:

```python
from guard_core.handlers.cloud_handler import cloud_handler_for

# The module-level objects are the default app's. Take the ones of the app
# you act on with the config that app was built with.
clouds = cloud_handler_for(security_config)


@app.get("/check-cloud/{ip}")
async def check_cloud_ip(ip: str):
    is_cloud = clouds.is_cloud_ip(ip, providers={"AWS", "GCP", "Azure"})
    return {"ip": ip, "is_cloud": is_cloud}
```
