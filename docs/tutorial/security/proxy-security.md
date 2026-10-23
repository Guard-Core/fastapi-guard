---

title: Proxy Security - FastAPI Guard
description: Secure handling of X-Forwarded-For headers and proxy configurations in FastAPI Guard
keywords: proxy security, X-Forwarded-For, header security, IP spoofing prevention
---

Proxy Security
==============

When your application is behind a proxy, load balancer, or CDN, properly handling the `X-Forwarded-For` header is critical for security. FastAPI Guard implements a secure approach to prevent IP spoofing attacks.

___

The Problem
-----------

The `X-Forwarded-For` header is sent by proxies to identify the original client IP, but since it can be manipulated by clients, it poses a security risk if trusted blindly.

Common security issues include:

- IP spoofing to bypass IP-based access controls
- False attribution in security logs
- Bypassing rate limiting and IP bans

___

Prerequisite: Your App Server Must Not Pre-Resolve the Client
---------------------------------------------------------------

FastAPI Guard reads the connecting IP from `request.client.host`, which is whatever your ASGI server put in `scope["client"]` - by the time a request reaches `SecurityMiddleware`, the server has already run. Several ASGI/WSGI servers rewrite that value themselves from `X-Forwarded-For` before any application code runs. uvicorn is the clearest example: it defaults to `proxy_headers=True` with `forwarded_allow_ips="127.0.0.1,::1"`, so a reverse proxy connecting from loopback (a same-host `proxy_pass`, the common case) has its `X-Forwarded-For` applied to `scope["client"]` upstream of FastAPI Guard.

When that happens, `trusted_proxies` unset does **not** mean "`X-Forwarded-For` is never trusted" - the server already trusted it, so an attacker's own forged header value becomes the connecting IP as far as rate limiting, IP bans, and every other check are concerned. guard-core detects the fingerprint of this condition (the connecting IP appearing inside its own `X-Forwarded-For` chain, which a real proxy never produces) and logs one warning naming the fix, but it cannot recover the true peer once the server has already overwritten it.

**Fix**: disable the server's own forwarded-header handling and let `trusted_proxies` be the single authority:

- uvicorn: `--no-proxy-headers` on the CLI, or `proxy_headers=False` in `uvicorn.run(...)`.
- Hypercorn has no server flag that does this; it rewrites `scope["client"]` from `X-Forwarded-For` only if you wrap the app in `hypercorn.middleware.ProxyFixMiddleware`, so leave that wrapper out and let `trusted_proxies` resolve the client.

!!! warning "`--forwarded-allow-ips='*'` lets a client choose its own identity"
    uvicorn's `ProxyHeadersMiddleware` rewrites `scope["client"]` from `X-Forwarded-For` before FastAPI Guard runs, for every connection whose peer address matches `--forwarded-allow-ips` (the `FORWARDED_ALLOW_IPS` environment variable, default `127.0.0.1,::1`). With `--forwarded-allow-ips='*'` (or `FORWARDED_ALLOW_IPS=*`) every peer matches, so a client that reaches uvicorn directly sends a different `X-Forwarded-For` on each request and rate limits, bans and every other check see a new identity each time. In a test with `rate_limit=3`, six requests with rotating `X-Forwarded-For` all returned 200 under `--forwarded-allow-ips='*'`, and 200 200 200 429 429 429 with `--no-proxy-headers`. To keep `trusted_proxies` the single authority, either pass `--no-proxy-headers`, or list in `--forwarded-allow-ips` exactly the addresses you list in `trusted_proxies` and never `*`.

With the server's own handling off, its access log will show the proxy's address rather than the original client - that's expected, since `X-Forwarded-For` is no longer applied before the request reaches your application.

___

Unix Sockets and Serverless Adapters
-------------------------------------

Some deployments never populate `request.client`: a Unix domain socket has no peer address, and some serverless ASGI adapters (Mangum, on certain event shapes) also yield `client=None`. Since guard-core 3.14.0, FastAPI Guard rejects such a request with 403 (`fail_secure=True`, the default) or runs the pipeline with identity `"unknown"` (`fail_secure=False`, allowed unless a whitelist or a country allow-list is configured; blacklist, country, and cloud checks cannot match without an address; detection and the shared rate-limit bucket still apply), logging a one-time warning either way.

If the connection is fronted by a reverse proxy that sets `X-Forwarded-For` (nginx over a Unix socket to uvicorn, for example), add the literal string `"unix"` to `trusted_proxies` so a peer-less connection is still treated as a trusted hop:

```python
config = SecurityConfig(
    trusted_proxies=["unix"],
    trusted_proxy_depth=1,
)
```

With `"unix"` configured, guard-core reads `X-Forwarded-For` exactly as it would for a normal trusted proxy, resolving the real client for rate limiting, IP bans, and every other check. Without it, every request over that socket resolves to `"unknown"`.

___

Secure Configuration
--------------------

FastAPI Guard implements a secure-by-default approach where X-Forwarded-For headers are only trusted from explicitly configured trusted proxies:

```python
config = SecurityConfig(
    trusted_proxies=["10.0.0.1", "192.168.1.0/24"],  # List of trusted proxy IPs/ranges
    trusted_proxy_depth=1,  # Number of proxies in the chain (default: 1)
    trust_x_forwarded_proto=True,  # Whether to trust X-Forwarded-Proto for HTTPS detection
)
```

___

How It Works
------------

1. When a request arrives, FastAPI Guard checks if it's from a trusted proxy
2. If not from a trusted proxy, the direct connecting IP is always used
3. If from a trusted proxy, the X-Forwarded-For header is parsed to extract the original client IP
4. The extracted IP is then used for all security checks

___

Configuration Options
---------------------

trusted_proxies
---------------

List of IP addresses or CIDR ranges that are allowed to set X-Forwarded-For headers:

```python
config = SecurityConfig(
    trusted_proxies=[
        "10.0.0.1",  # Single IP
        "192.168.1.0/24",  # CIDR range
        "172.16.0.0/16",  # Another CIDR range
    ]
)
```

If empty (default), X-Forwarded-For headers will not be trusted at all.

trusted_proxy_depth
-------------------

Controls how the client IP is extracted from the X-Forwarded-For header:

```python
config = SecurityConfig(
    trusted_proxies=["10.0.0.1"],
    trusted_proxy_depth=2,  # Assumes two proxies in the chain
)
```

The X-Forwarded-For format is: `client, proxy1, proxy2, ...` (leftmost is the original client)

- With depth=1 (default): Assumes one proxy in chain, uses leftmost IP as client
- With depth=2: Assumes two proxies in chain, still uses leftmost IP
- Higher values handle more complex proxy chains

trust_x_forwarded_proto
-----------------------

Whether to trust the X-Forwarded-Proto header for HTTPS detection:

```python
config = SecurityConfig(
    trusted_proxies=["10.0.0.1"],
    trust_x_forwarded_proto=True,  # Trust X-Forwarded-Proto from trusted proxies
)
```

This only applies when the request comes from a trusted proxy.

___

Real-World Examples
-------------------

Single Reverse Proxy
---------------------

```python
config = SecurityConfig(
    trusted_proxies=["10.0.0.1"],  # Your Nginx/HAProxy IP
    trusted_proxy_depth=1,  # One proxy
    trust_x_forwarded_proto=True,  # Trust HTTPS status from proxy
)
```

Load Balancer + Proxy
---------------------

```python
config = SecurityConfig(
    trusted_proxies=[
        "10.0.0.1",  # Load balancer IP
        "192.168.1.0/24",  # Internal proxy subnet
    ],
    trusted_proxy_depth=2,  # Two proxies in chain
    trust_x_forwarded_proto=True,
)
```

Cloud Provider Load Balancer
-----------------------------

```python
config = SecurityConfig(
    trusted_proxies=[
        "10.0.0.0/8"  # Cloud provider's internal IP range
    ],
    trusted_proxy_depth=1,
    trust_x_forwarded_proto=True,
)
```

___

Best Practices
--------------

1. **Be specific**: Only include the exact IPs or ranges of your known proxies
2. **Use correct depth**: Configure based on your actual proxy chain
3. **Regular audits**: Periodically review your trusted proxy list
4. **Test configuration**: Verify correct IP extraction in your environment
