---

title: IP Banning - FastAPI Guard
description: Implement automatic and manual IP banning in FastAPI applications using FastAPI Guard's IPBanManager
keywords: ip banning, ip blocking, security middleware, fastapi security
---

IP Banning
==========

FastAPI Guard provides powerful IP banning capabilities through the `IPBanManager`.

___

Automatic IP Banning
---------------------

Configure automatic IP banning based on suspicious activity:

```python
config = SecurityConfig(
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    auto_ban_duration=3600,  # Ban duration in seconds (1 hour)
)
```

___

Manual IP Banning
------------------

You can also manually ban IPs using the `IPBanManager`:

```python
from guard_core.handlers.ipban_handler import ip_ban_manager_for

# The module-level objects are the default app's. Take the ones of the app
# you act on with the config that app was built with.
bans = ip_ban_manager_for(security_config)


@app.post("/admin/ban/{ip}")
async def ban_ip(ip: str, duration: int = 3600):
    await bans.ban_ip(ip, duration)
    return {"message": f"IP {ip} banned for {duration} seconds"}
```

___

Checking Ban Status
-------------------

Check if an IP is currently banned:

```python
@app.get("/admin/check/{ip}")
async def check_ban(ip: str):
    is_banned = await bans.is_ip_banned(ip)
    return {"ip": ip, "banned": is_banned}
```

___

Reset All Bans
--------------

Clear all active IP bans:

```python
@app.post("/admin/reset")
async def reset_bans():
    await bans.reset()
    return {"message": "All IP bans cleared"}
```
