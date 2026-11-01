---

title: SecurityMiddleware API - FastAPI Guard
description: Complete API reference for FastAPI Guard's SecurityMiddleware class and its configuration options
keywords: security middleware, fastapi middleware, api security, middleware configuration
---

SecurityMiddleware
==================

The `SecurityMiddleware` class is the core component of FastAPI Guard that handles all security features.

!!! info "Architecture (v4.2.0+)"
    Since v4.2.0, SecurityMiddleware uses a modular architecture with specialized core modules. The middleware acts as an orchestration layer, delegating to specialized handlers. See [Core Architecture](core-architecture.md) for internal details.

___

Class Definition
----------------

```python
class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(
        self, app: Callable[[Request], Awaitable[Response]], *, config: SecurityConfig
    ):
        """
        Initialize the SecurityMiddleware.

        Args:
            app: The FastAPI/Starlette application
            config: Security configuration object

        Note:
            The middleware initializes all core components using
            dependency injection for clean separation of concerns.
        """
```

___

Architecture Overview
---------------------

Request Processing Flow
-----------------------

The middleware processes requests through a modular pipeline:

```text
Request → Middleware.dispatch()
    ↓
1. BypassHandler.handle_passthrough()
    ├─ No client address? → 403 under fail_secure (the default); logged and admitted in passive_mode
    └─ Excluded path? → Pass through
    ↓
2. Extract client IP and route config
    ↓
3. BypassHandler.handle_security_bypass()
    └─ Decorator bypass? → Pass through
    ↓
4. SecurityCheckPipeline.execute()
    ├─ RouteConfigCheck
    ├─ EmergencyModeCheck
    ├─ HttpsEnforcementCheck
    ├─ RequestLoggingCheck
    ├─ RequestSizeContentCheck
    ├─ RequiredHeadersCheck
    ├─ AuthenticationCheck
    ├─ ReferrerCheck
    ├─ CustomValidatorsCheck
    ├─ TimeWindowCheck
    ├─ CloudIpRefreshCheck
    ├─ IpSecurityCheck
    ├─ CloudProviderCheck
    ├─ UserAgentCheck
    ├─ RateLimitCheck
    ├─ SuspiciousActivityCheck
    └─ CustomRequestCheck
    ↓
5. BehavioralProcessor.process_usage_rules()
    ↓
6. call_next(request)  # Forward to app
    ↓
7. ErrorResponseFactory.process_response()
    ├─ Apply security headers
    ├─ Apply CORS headers
    ├─ Collect metrics
    └─ Process behavioral return rules
    ↓
Response
```

Core Components
---------------

The middleware delegates to these specialized modules:

- **SecurityCheckPipeline**: Executes security checks in sequence
- **SecurityEventBus**: Sends security events to monitoring agent
- **MetricsCollector**: Collects request/response metrics
- **HandlerInitializer**: Initializes Redis and Agent handlers
- **ErrorResponseFactory**: Creates and processes responses
- **RouteConfigResolver**: Resolves decorator configurations
- **RequestValidator**: Validates request properties
- **BypassHandler**: Handles security bypasses
- **BehavioralProcessor**: Processes behavioral rules

See [Core Architecture](core-architecture.md) for detailed documentation of each module.

___

Public Methods
--------------

dispatch
--------

```python
async def dispatch(
    self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """
    Main request handler that orchestrates security checks.

    This method is pure orchestration - it delegates all logic
    to specialized handlers and maintains no business logic itself.

    Args:
        request: The incoming request
        call_next: The next middleware/handler in the chain

    Returns:
        Response: Either from security checks (blocking) or from the app

    Flow:
        1. Handle passthrough cases (no client, excluded paths)
        2. Get route config and client IP
        3. Handle security bypasses
        4. Execute security pipeline
        5. Process behavioral usage rules
        6. Call next handler
        7. Process response (headers, metrics, behavioral return rules)
    """
```

create_error_response
---------------------

```python
async def create_error_response(
    self, status_code: int, default_message: str
) -> Response:
    """
    Create standardized error responses.

    Delegates to ErrorResponseFactory for response creation.

    Args:
        status_code: HTTP status code
        default_message: Default error message

    Returns:
        Response: Error response with optional custom message

    Note:
        Custom error messages can be configured in SecurityConfig
        via the custom_error_responses dict.
    """
```

initialize
----------

```python
async def initialize(self) -> None:
    """
    Initialize all components asynchronously.

    Tasks performed:
        - Build security check pipeline
        - Initialize Redis handlers (if enabled)
        - Initialize agent integrations (if enabled)
        - Initialize dynamic rule manager (if configured)
    """
```

`initialize` is part of the public API for advanced integration scenarios, but most applications should not call it directly. The recommended path is to wire FastAPI Guard's lifespan helper at app construction time:

```python
from fastapi import FastAPI
from guard.lifespan import guard_lifespan
from guard.middleware import SecurityMiddleware
from guard import SecurityConfig

config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")

app = FastAPI(lifespan=guard_lifespan)
app.add_middleware(SecurityMiddleware, config=config)
```

If you already have a custom lifespan, compose them with `make_lifespan`:

```python
from contextlib import asynccontextmanager
from guard.lifespan import make_lifespan


@asynccontextmanager
async def my_lifespan(app):
    yield


app = FastAPI(lifespan=make_lifespan(my_lifespan))
app.add_middleware(SecurityMiddleware, config=config)
```

If a host framework owns the `lifespan` slot and only exposes its own startup-hook API - NiceGUI's `app.on_startup`, for example - await `guard_startup(app)` from that hook instead:

```python
from nicegui import app
from guard.lifespan import guard_startup
from guard.middleware import SecurityMiddleware
from guard import SecurityConfig

config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
app.add_middleware(SecurityMiddleware, config=config)


async def _warm_up_guard() -> None:
    await guard_startup(app)


app.on_startup(_warm_up_guard)
```

NiceGUI's `app.on_startup` takes the handler as an argument; it is not a decorator, so `@app.on_startup` is wrong (it returns `None` and rebinds your function). It runs once at app boot, from NiceGUI's FastAPI lifespan, before the server accepts connections, not per client (per client is `app.on_connect`). These warm-up helpers warm guard-core's singletons (cloud-IP cache, IP ban store, suspicious patterns, Redis pool) AND populate a shared-state registry so the live request-handling middleware adopts the spawned instance's pipeline, agent handler, and event bus by reference. This guarantees `composite_handler.start()` runs exactly once per config - no duplicate OTEL `set_tracer_provider already set` warning, no leaked agent worker tasks. `guard_startup` performs exactly what `guard_lifespan` does on entry, so it shares the same idempotency: a second call finds the state already registered and adopts it instead of re-initializing, which keeps the once-at-boot goal safe even under NiceGUI's reload/restart.

Decorator Visibility Shapes the Pipeline
------------------------------------------

guard-core 3.10.0 builds `security_pipeline` from the effective configuration in `_build_security_pipeline()` and skips checks that configuration can never trigger. Six of those checks are driven purely by per-route decorators, and guard-core can only skip them when it can enumerate the registered route configuration through the middleware's `guard_decorator` attribute. `_ensure_initialized()` resolves `self.guard_decorator` from `app.state.guard_decorator` via `adopt_app_state_decorator()` before it calls `initialize()`, and the three startup paths above (`guard_lifespan`, `make_lifespan`, `guard_startup`) resolve it the same way through the same underlying `resolve_app_state_decorator()` helper before they warm or adopt state. When no decorator handler can be found, route configuration is treated as unknown and every route-driven check is kept, so this resolution step can only lose the smaller pipeline, never the protection those checks provide. This is a separate mechanism from behavioral rule firing (see [Behavioral Analysis Decorators](../tutorial/decorators/behavioral.md)), which re-reads `app.state.guard_decorator` on every request rather than once at initialization.

mark_initialized
----------------

```python
def mark_initialized(self) -> None:
    """Record that initialization has completed."""
```

`mark_initialized` is the public setter the lifespan helpers call after they finish warming or adopting state. It flips the internal initialization flag so the first request does not re-trigger lazy init. User code rarely needs to call this directly; the lifespan helpers handle it.

get_initialization_status
--------------------------

```python
def get_initialization_status(self) -> dict[str, Any]:
    """
    Report cloud-provider and geo-IP warmup state.

    Delegates to guard-core's HandlerInitializer.get_initialization_status()
    and JSON-encodes the result (datetimes become ISO 8601 strings).
    """
```

Synchronous and dependency-free - safe to call from a health check or warmup probe on every hit. See [Initialization Status](../tutorial/configuration/security-config.md#initialization-status) for the response shape and `guard.status.add_status_route` for an opt-in HTTP wrapper around it.

set_decorator_handler
---------------------

```python
def set_decorator_handler(
    self,
    decorator_handler: BaseSecurityDecorator | None
) -> None:
    """
    Set the SecurityDecorator instance for decorator support.

    This enables route-level security configuration via decorators.

    Args:
        decorator_handler: SecurityDecorator instance or None

    Example:
        ```python
        guard_deco = SecurityDecorator(config)
        middleware.set_decorator_handler(guard_deco)
        # Or set on app state:
        app.state.guard_decorator = guard_deco
        ```
    """
```

___

State Sharing via the Shared-State Registry
-------------------------------------------

FastAPI Guard maintains a module-local registry at `guard._middleware_state`, keyed by `(id(config), id(guard_decorator))`. The registry holds a `MiddlewareState` dataclass containing the live `security_pipeline`, `composite_handler`, `event_bus`, `metrics_collector`, `response_factory`, `validator`, `bypass_handler`, `behavioral_processor`, `handler_initializer`, and `agent_handler`.

When multiple `SecurityMiddleware` instances are constructed against the same `SecurityConfig` and resolve the same decorator handler - the common case under the lifespan helpers (where one instance is spawned to perform warmup while Starlette later constructs the live request-handling instance), and the sub-app mounted-middleware case where every sub-app shares one decorator - every instance after the first adopts the registered components by reference instead of building its own.

The keying is intentional: since guard-core 3.10 the pipeline is derived from route configuration as well as config, so config identity alone is not a safe cache key. Two `SecurityMiddleware` instances sharing a `SecurityConfig` but resolving different `guard_decorator` handlers (for example, two sub-apps mounted under one root app, each with its own decorated routes) get separate registry entries and each builds its own pipeline. Two `SecurityConfig` instances with identical contents but separate `id()` values also get separate registry entries, because they are logically distinct configurations. If you want shared state, share both the config object and the decorator handler.

The practical effect is that `composite_handler.start()` - which sets the OTEL/Logfire global tracer providers and starts the agent worker tasks - runs exactly once per config object. No duplicate `set_tracer_provider already set` warning, no leaked agent worker tasks, no duplicate buffered events.

___

Handler Integration
-------------------

The middleware works with singleton handler instances:

- All handler classes (IPBanManager, CloudManager, etc.) use the singleton pattern
- The middleware initializes these existing instances conditionally based on configuration
- IPInfoManager is only initialized when country filtering is enabled
- CloudManager is only loaded when cloud provider blocking is configured
- This selective loading improves performance when not all features are used

Initialization Process
-----------------------

The middleware uses `HandlerInitializer` to set up all handlers:

```python
# In __init__
self.handler_initializer = HandlerInitializer(
    config=self.config,
    redis_handler=self.redis_handler,
    agent_handler=self.agent_handler,
    geo_ip_handler=self.geo_ip_handler,
    rate_limit_handler=self.rate_limit_handler,
    guard_decorator=self.guard_decorator,
)

# In initialize()
await self.handler_initializer.initialize_redis_handlers()
await self.handler_initializer.initialize_agent_integrations()
```

___

Redis Configuration
-------------------

Enable Redis in SecurityConfig:

```python
config = SecurityConfig(
    enable_redis=True, redis_url="redis://prod:6379/0", redis_prefix="prod_security:"
)
```

The middleware automatically initializes:

- CloudManager cloud provider IP ranges
- IPBanManager distributed banning
- IPInfoManager IP geolocation
- RateLimitManager rate limiting
- RedisManager Redis caching
- SusPatternsManager suspicious patterns

___

Proxy Security Configuration
----------------------------

The middleware supports secure handling of proxy headers:

```python
config = SecurityConfig(
    trusted_proxies=["10.0.0.1", "192.168.1.0/24"],  # List of trusted proxy IPs/ranges
    trusted_proxy_depth=1,  # Number of proxies in the chain
    trust_x_forwarded_proto=True,  # Trust X-Forwarded-Proto header from trusted proxies
)
```

This prevents IP spoofing attacks through header manipulation.

___

Usage Examples
--------------

Basic Setup
-----------

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard import SecurityConfig

app = FastAPI()

config = SecurityConfig(rate_limit=100, enforce_https=True, enable_cors=True)

app.add_middleware(SecurityMiddleware, config=config)
```

With Decorators
---------------

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard import SecurityConfig
from guard import SecurityDecorator

app = FastAPI()

config = SecurityConfig(rate_limit=100)
guard_deco = SecurityDecorator(config)


# Apply decorators to routes
@app.get("/api/limited")
@guard_deco.rate_limit(requests=10, window=300)
def limited_endpoint():
    return {"data": "limited"}


# Add middleware and set decorator
app.add_middleware(SecurityMiddleware, config=config)
app.state.guard_decorator = guard_deco  # Required for decorator integration
```

With Eager Initialization (Lifespan)
------------------------------------

```python
from fastapi import FastAPI
from guard.lifespan import guard_lifespan
from guard.middleware import SecurityMiddleware
from guard import SecurityConfig

config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")

app = FastAPI(lifespan=guard_lifespan)
app.add_middleware(SecurityMiddleware, config=config)
```

`guard_lifespan` runs the full initialization sequence at ASGI startup so the first request hits a pre-warmed middleware. Use `make_lifespan(existing)` to compose with your own lifespan context manager, or `guard_startup(app)` from a host framework's own startup hook (e.g. NiceGUI's `app.on_startup`) when it owns the `lifespan` slot and you cannot pass one in - see [Eager Initialization](../tutorial/first-steps.md#eager-initialization-with-fastapi-lifespan) for all three.

___

Internal Architecture
---------------------

!!! note "For Contributors"
    The internal architecture is documented in [Core Architecture](core-architecture.md). This section provides a high-level overview.

Modular Design (v4.2.0+)
-------------------------

The middleware delegates to specialized modules in `guard_core/core/`:

- **checks/**: Security check implementations (Chain of Responsibility pattern)
- **events/**: Event bus and metrics collection
- **initialization/**: Handler initialization logic
- **responses/**: Response creation and processing
- **routing/**: Route configuration resolution
- **validation/**: Request validation utilities
- **bypass/**: Security bypass handling
- **behavioral/**: Behavioral rule processing

Benefits of Modular Architecture
--------------------------------

- **Maintainability**: Each check is a class in its own module under `guard_core/core/checks/implementations/`. Of the 69 modules under `guard_core/core/`, 51 are 200 lines or shorter and the largest is 798 lines (`checks/helpers.py`), measured on guard-core 5.0.0 with `find guard_core/core -name '*.py' ! -name '__init__.py' | xargs wc -l` from a guard-core checkout
- **Testability**: Each component independently testable
- **Performance**: Better caching and optimization opportunities
- **Extensibility**: Easy to add new checks or modify behavior
- **Development Speed**: A new check is one `SecurityCheck` subclass in its own module plus its entry in `checks/factory.py`. The 18 checks written so far take 35 to 512 lines (median 140). No speed-up is measured, so the page states none

___

See Also
--------

- [Core Architecture](core-architecture.md) - Detailed internal architecture
- [SecurityConfig](../tutorial/configuration/security-config.md) - Configuration options
- [Decorators](decorators.md) - Route-level security
- [API Overview](overview.md) - Complete API reference
