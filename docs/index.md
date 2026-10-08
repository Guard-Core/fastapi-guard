---

title: FastAPI Guard - Security Middleware for FastAPI
description: Comprehensive security library for FastAPI applications providing IP control, request logging, and penetration detection
keywords: fastapi, security, middleware, python, ip control, penetration detection, cybersecurity
---

FastAPI Guard
=============

![FastAPI Guard Logo](assets/fastapi_guard_legend.svg)

[![PyPI version](https://badge.fury.io/py/fastapi-guard.svg?cache=none&icon=si%3Apython&icon_color=%23008cb4)](https://badge.fury.io/py/fastapi-guard)
[![Release](https://github.com/Guard-Core/fastapi-guard/actions/workflows/release.yml/badge.svg)](https://github.com/Guard-Core/fastapi-guard/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Guard-Core/fastapi-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Guard-Core/fastapi-guard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Guard-Core/fastapi-guard/actions/workflows/code-ql.yml/badge.svg)](https://github.com/Guard-Core/fastapi-guard/actions/workflows/code-ql.yml)

[![pages-build-deployment](https://github.com/Guard-Core/fastapi-guard/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages)](https://github.com/Guard-Core/fastapi-guard/actions/workflows/pages/pages-build-deployment)
[![Docs Update](https://github.com/Guard-Core/fastapi-guard/actions/workflows/docs.yml/badge.svg)](https://github.com/Guard-Core/fastapi-guard/actions/workflows/docs.yml)
[![Downloads](https://pepy.tech/badge/fastapi-guard)](https://pepy.tech/project/fastapi-guard)

`fastapi-guard` is a comprehensive security library for FastAPI applications, providing middleware to control IPs, log requests, and detect penetration attempts. It integrates seamlessly with FastAPI to offer robust protection against various security threats, ensuring your application remains secure and reliable.

___

Quick Start
-----------

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard import SecurityConfig
from guard import IPInfoManager

app = FastAPI()

config = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_token_here"),
    enable_redis=False,
    rate_limit=100,
    auto_ban_threshold=5,
)

app.add_middleware(SecurityMiddleware, config=config)
```

___

Example App
-----------

Inside [examples](https://github.com/Guard-Core/fastapi-guard/tree/master/examples), you can find a simple example app that demonstrates how to use FastAPI Guard.

___

Live Playground
---------------

Try FastAPI Guard features directly in your browser:

**<https://playground.guard-core.com>**

This interactive demo allows you to explore FastAPI Guard's capabilities without any setup.

___

Docker Container
----------------

You can also download the example app as a Docker container from [GitHub Container Registry](https://github.com/orgs/Guard-Core/packages/container/fastapi-guard-example).

```bash
# Pull the latest version
docker pull ghcr.io/guard-core/fastapi-guard-example:latest

# Or pull a specific version (matches library releases)
docker pull ghcr.io/guard-core/fastapi-guard-example:v8.0.3
```

___

Running the Example App
-----------------------

Using Docker Compose (Recommended)
-----------------------------------

The easiest way to run the example app is with Docker Compose, which automatically sets up Redis:

```bash
# Clone the repository
git clone https://github.com/Guard-Core/fastapi-guard.git
cd fastapi-guard/examples

# Start the app with Redis
docker compose up
```

This will start both the FastAPI Guard example app and Redis service. The app will be available at <http://0.0.0.0:8000>.

Using Docker Container Only
----------------------------

Alternatively, you can run just the container:

```bash
# Run with default settings
docker run --host 0.0.0.0 -p 8000:8000 ghcr.io/guard-core/fastapi-guard-example:latest

# Run with custom Redis connection
docker run --host 0.0.0.0 -p 8000:8000 \
 -e REDIS_URL=redis://your-redis-host:your-redis-port \
 -e REDIS_PREFIX=your-redis-prefix \
 -e IPINFO_TOKEN=your-ipinfo-token \
 ghcr.io/guard-core/fastapi-guard-example:latest
```

The example app includes endpoints to test various security features of FastAPI Guard. Access the Swagger documentation at <http://0.0.0.0:8000/docs> after running the container.

___

Features
--------

- **IP Whitelisting and Blacklisting**: Control access based on IP addresses.
- **User Agent Filtering**: Block requests from specific user agents.
- **Rate Limiting**: Limit the number of requests from a single IP.
- **Automatic IP Banning**: Automatically ban IPs after a certain number of suspicious requests.
- **Penetration Attempt Detection**: Detect and log potential penetration attempts.
- **Custom Logging**: Log security events to a custom file.
- **CORS Configuration**: Configure CORS settings for your FastAPI application.
- **Cloud Provider IP Blocking**: Block requests from cloud provider IPs (AWS, GCP, Azure).
- **IP Geolocation**: Use IPInfo.io API to determine the country of an IP address.
- **Optimized Performance**: Selective loading of external resources based on configuration.
- **Flexible Storage**: Choose between Redis-backed distributed state or in-memory storage.
- **Automatic Fallback**: Seamless operation with/without Redis connection.
- **Secure Proxy Handling**: Protection against X-Forwarded-For header injection attacks

___

Documentation
-------------

- [Installation](installation.md)
- [First Steps](tutorial/first-steps.md)
- [IP Management](tutorial/ip-management/banning.md)
- [Rate Limiting](tutorial/ip-management/rate-limiter.md)
- [API Reference](api/overview.md)
- [Redis Integration Guide](tutorial/redis-integration/caching.md)
- [Example App](tutorial/examples/example-app.md)

[📖 **Learn More in the Tutorial**](tutorial/first-steps.md)

___

What's New
----------

FastAPI Guard now has a centralized cloud platform for monitoring, threat analysis, and rule management across all your apps.

- **Real-time security dashboard** at [app.guard-core.com](https://app.guard-core.com)
- **Threat intelligence** --- attack patterns, geographic breakdowns, severity scoring
- **Dynamic rules** --- update security configuration from the dashboard without redeploying
- **GDPR compliance** --- consent management, data export, account deletion
- **Free tier** --- 10K events/month on the Individual plan

Connect your existing setup in 2 minutes with [`guard-agent`](https://pypi.org/project/guard-agent/):

```bash
uv add guard-agent
```

Then add the agent fields to your existing `SecurityConfig` — that's the entire integration. The middleware drives the agent's lifecycle for you; **no `AgentConfig`, no `lifespan` hook, no manual `start()/stop()` required.**

```python
config = SecurityConfig(
    rate_limit=100,
    auto_ban_threshold=5,
    enable_penetration_detection=True,
    # Telemetry — that's it
    enable_agent=True,
    agent_api_key="YOUR_API_KEY",
    agent_project_id="YOUR_PROJECT_ID",
)

app.add_middleware(SecurityMiddleware, config=config)
```

See the [Integration Guide](tutorial/integration.md) for the full decision tree (standalone / SaaS / encrypted SaaS), credentials setup, and common pitfalls.

The [Playground](https://playground.guard-core.com) shows real attack data from a live server --- see what gets blocked and why before connecting your own apps.
