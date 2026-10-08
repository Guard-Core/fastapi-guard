---

title: API Reference - FastAPI Guard
description: Complete API documentation for FastAPI Guard security middleware and its components
keywords: fastapi guard api, security middleware api, python api reference
---

API Reference Overview
======================

!!! info "Architecture Update (v5.0.0)"
    As of v5.0.0, FastAPI Guard is a thin adapter over [guard-core](https://github.com/Guard-Core/guard-core). All core security modules now live in the `guard_core` package. The public API remains unchanged — use `from guard import ...` for all imports. See [Core Architecture](core-architecture.md) for details.

___

Core Components
---------------

Middleware & Configuration
----------------------------

- **[SecurityMiddleware](security-middleware.md)**: The main middleware that handles all security features
- **[SecurityConfig](../tutorial/configuration/security-config.md)**: Configuration class for all security settings
- **[SecurityDecorator](decorators.md)**: Route-level security decorator system

Internal Core Modules (v4.2.0+)
--------------------------------

!!! warning "Internal Implementation"
    These modules are internal implementation details. Always use the public API (`SecurityMiddleware`, `SecurityConfig`, `SecurityDecorator`).

    Documentation provided for contributors and advanced users.

- **[Core Architecture](core-architecture.md)**: Complete internal architecture documentation
  - **SecurityCheckPipeline**: Chain of Responsibility pattern for security checks
  - **SecurityEventBus**: Centralized event dispatching
  - **MetricsCollector**: Request/response metrics collection
  - **HandlerInitializer**: Handler initialization logic
  - **ErrorResponseFactory**: Response creation and processing
  - **RouteConfigResolver**: Route configuration resolution
  - **RequestValidator**: Request validation utilities
  - **BypassHandler**: Security bypass handling
  - **BehavioralProcessor**: Behavioral rule processing

Handler Components
------------------

- **[IPBanManager](ipban-manager.md)**: Manages IP banning functionality
- **[IPInfoManager](ipinfo-manager.md)**: Handles IP geolocation using IPInfo's database
- **[SusPatternsManager](sus-patterns.md)**: Manages suspicious patterns for threat detection
- **[CloudManager](cloud-manager.md)**: Handles cloud provider IP range detection
- **[RateLimitManager](ratelimit-manager.md)**: Handles rate limiting functionality
- **[RedisManager](redis-manager.md)**: Handles Redis connections and atomic operations
- **[BehaviorTracker](behavior-manager.md)**: Handles behavioral analysis and monitoring
- **[SecurityHeadersManager](security-headers.md)**: Manages security headers

Utilities
---------

- **[Utilities](utilities.md)**: Helper functions for logging and request analysis

___

Key Classes and Instances
-------------------------

```python
# Core middleware and configuration
from guard.middleware import SecurityMiddleware
from guard import SecurityConfig

# Security decorators
from guard import SecurityDecorator, RouteConfig
from guard_core.decorators.base import get_route_decorator_config

# Handler classes and their pre-initialized instances
from guard import CloudManager, cloud_handler
from guard import IPBanManager, ip_ban_manager
from guard import RateLimitManager, rate_limit_handler
from guard import RedisManager, redis_handler
from guard import sus_patterns_handler  # SusPatternsManager singleton instance
from guard import BehaviorTracker, BehaviorRule

# Special case - requires parameters
from guard import IPInfoManager
```

___

Singleton Pattern
-----------------

Most handler classes use a singleton pattern with `__new__` to ensure only one instance:

```python
class ExampleHandler:
    _instance = None

    def __new__(cls, *args, **kwargs) -> "ExampleHandler":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            # Initialize instance attributes
        return cls._instance
```

___

Configuration Model
-------------------

The `SecurityConfig` class is the central configuration point. It is a Pydantic model, not a hand-written `__init__`; the fields below (with their real defaults) are a subset shown for orientation, see [Security Config](../tutorial/configuration/security-config.md) for the complete field list:

```python
class SecurityConfig(BaseModel):
    geo_ip_handler: GeoIPHandler | None = None
    whitelist: list[str] | None = None
    blacklist: list[str] = []
    blocked_countries: frozenset[str] = frozenset()
    whitelist_countries: frozenset[str] = frozenset()
    blocked_user_agents: list[str] = []
    auto_ban_threshold: int = 10
    auto_ban_duration: int = 3600
    rate_limit: int = 10
    rate_limit_window: int = 60
    enable_cors: bool = False
    # ... other fields
```

___

Optimized Loading
-----------------

FastAPI Guard uses a smart loading strategy to improve performance:

- **IPInfoManager**: Only downloaded and initialized when country filtering is configured
- **CloudManager**: Only fetches cloud provider IP ranges when cloud blocking is enabled
- **Handlers Initialization**: Middleware conditionally initializes components based on configuration

This approach reduces startup time and memory usage when not all security features are needed.

By default initialization runs lazily on the first request. For production deployments, wire `guard_lifespan` so initialization runs at ASGI startup instead — see [Eager initialization with FastAPI lifespan](../tutorial/first-steps.md#eager-initialization-with-fastapi-lifespan).

```python
# Conditional loading example from middleware
async def initialize(self) -> None:
    if self.config.enable_redis and self.redis_handler:
        await self.redis_handler.initialize()
        # Only initialize when needed
        if self.config.block_cloud_providers:
            await cloud_handler.initialize_redis(
                self.redis_handler, self.config.block_cloud_providers
            )
        await ip_ban_manager.initialize_redis(self.redis_handler)
        # Only initialize if country filtering is enabled
        if self.geo_ip_handler is not None:
            await self.geo_ip_handler.initialize_redis(self.redis_handler)
```

___

Security Decorators
-------------------

FastAPI Guard provides a comprehensive decorator system for route-level security controls:

SecurityDecorator Class
----------------------------

The main decorator class combines all security capabilities:

```python
from guard import SecurityDecorator

config = SecurityConfig()
guard_deco = SecurityDecorator(config)


# Apply to routes
@app.get("/api/sensitive")
@guard_deco.rate_limit(requests=5, window=300)
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])
@guard_deco.block_countries(["CN", "RU"])
def sensitive_endpoint():
    return {"data": "sensitive"}
```

___

Decorator Categories
-------------------

- **AccessControlMixin**: IP filtering, geographic restrictions, cloud provider blocking
- **AuthenticationMixin**: HTTPS enforcement, auth requirements, API key validation
- **RateLimitingMixin**: Custom rate limits, geographic rate limiting
- **BehavioralMixin**: Usage monitoring, return pattern analysis, frequency detection
- **ContentFilteringMixin**: Content type filtering, size limits, user agent blocking
- **AdvancedMixin**: Time windows, suspicious detection, honeypot detection

___

Integration with Middleware
----------------------------

Decorators work seamlessly with SecurityMiddleware:

```python
# Set up middleware and decorators
app.add_middleware(SecurityMiddleware, config=config)
app.state.guard_decorator = guard_deco  # Required for integration
```

___

Route Configuration Priority
----------------------------

Configuration is applied in the following order of precedence:

1. Decorator Settings (highest priority)
2. Global Middleware Settings
3. Default Settings (lowest priority)

This allows route-specific overrides while maintaining global defaults.

For IP and country access control, this priority applies per-aspect rather than as a blanket override: the global IP whitelist/blacklist and country rules always run on decorated routes. A route-level allow rule (`ip_whitelist` or `whitelist_countries`) suppresses the corresponding global gate. A route-level deny rule (`ip_blacklist` or `blocked_countries`) is additive and does not disable the global rules. Within the IP aspect, a route `ip_whitelist` match takes priority over that route's own `ip_blacklist` and over the global blacklist.
