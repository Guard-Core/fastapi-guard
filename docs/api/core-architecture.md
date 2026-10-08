---

title: Core Architecture - FastAPI Guard
description: Internal architecture documentation for FastAPI Guard's modular core system
keywords: core architecture, modular design, security checks, middleware internals

---

Core Architecture (Internal)
=============================

!!! warning "Internal Implementation Details"
    As of v5.0.0, all core modules live in the [guard-core](https://github.com/Guard-Core/guard-core) package (`guard_core/core/`). They should NOT be imported directly in user code. Always use the public API via `from guard import ...` or `from guard.middleware import SecurityMiddleware`.

    This documentation is provided for contributors and advanced users who want to understand the internal architecture.

___

Overview
--------

FastAPI Guard uses a modular core architecture introduced in v4.2.0 that separates security concerns into specialized, independently testable modules. This transformation improved maintainability from MI 0.00 (Rank C) to MI 54.51 (Rank A) while maintaining 100% backward compatibility.

Architecture Principles
------------------------

1. **Single Responsibility**: Each module has one clear purpose
2. **Dependency Injection**: Clean dependencies via context objects
3. **Chain of Responsibility**: Security checks execute in a pipeline
4. **Testability**: Each component independently testable
5. **Performance**: Better caching and optimization opportunities

Module Overview
----------------

```text
guard_core/core/
├── checks/              # Security check pipeline (Chain of Responsibility)
├── events/              # Event bus and metrics collection
├── initialization/      # Handler initialization logic
├── responses/           # Response creation and processing
├── routing/             # Route configuration resolution
├── validation/          # Request validation utilities
├── bypass/              # Security bypass handling
└── behavioral/          # Behavioral rule processing
```

___

Module: guard_core/core/checks/
--------------------------

**Purpose**: Security check implementations using the Chain of Responsibility pattern

**Pattern**: Pipeline-based execution where each check can block or pass the request

Key Components
--------------

SecurityCheck (Base Class)
--------------------------

Abstract base class for all security checks.

**Location**: `guard_core/core/checks/base.py`

**Key Methods**:

```python
class SecurityCheck:
    check_name: str  # Unique identifier for the check

    async def check(self, request: Request) -> Response | None:
        """Execute the security check. Return Response to block, None to pass."""
        ...

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> Response:
        """Create standardized error response."""
        ...
```

**Usage**: All security checks inherit from this base class.

SecurityCheckPipeline
---------------------

Orchestrates the execution of multiple security checks in sequence.

**Location**: `guard_core/core/checks/pipeline.py`

**Key Methods**:

```python
class SecurityCheckPipeline:
    def __init__(self, checks: list[SecurityCheck]):
        """Initialize pipeline with ordered list of checks."""
        ...

    async def execute(self, request: Request) -> Response | None:
        """Execute all checks. Returns first blocking response or None."""
        ...

    def get_check_names(self) -> list[str]:
        """Get names of all checks in execution order."""
        ...
```

**Features**:

- Sequential execution with early termination
- Error handling with fail-secure option
- Logging of blocking checks
- Dynamic check addition/removal

Check Implementations
---------------------

**Location**: `guard_core/core/checks/implementations/`

Execution Order
---------------

Checks execute in this order (defined in guard-core's `DEFAULT_CHECK_CLASSES`, `guard_core/core/checks/factory.py`):

1. **RouteConfigCheck** - Extract route config and client IP
2. **EmergencyModeCheck** - Emergency mode (highest priority)
3. **HttpsEnforcementCheck** - HTTPS enforcement (can redirect)
4. **RequestLoggingCheck** - Log request
5. **RequestSizeContentCheck** - Validate size/content
6. **RequiredHeadersCheck** - Check required headers
7. **AuthenticationCheck** - Verify authentication
8. **ReferrerCheck** - Check referrer
9. **CustomValidatorsCheck** - Custom validators
10. **TimeWindowCheck** - Time-based access
11. **CloudIpRefreshCheck** - Periodic maintenance
12. **IpSecurityCheck** - IP whitelist/blacklist
13. **CloudProviderCheck** - Cloud provider blocking
14. **UserAgentCheck** - User agent filtering
15. **RateLimitCheck** - Rate limiting
16. **SuspiciousActivityCheck** - Threat detection
17. **CustomRequestCheck** - Custom checks

Pipeline Construction Skips Checks Configuration Can Never Trigger
---------------------------------------------------------------------

`build_default_pipeline()` (`guard_core/core/checks/factory.py`) filters `DEFAULT_CHECK_CLASSES` through each check's `applies_to(config, route_configs)` classmethod before instantiating anything, so a check that configuration can never trigger is never built rather than merely skipped per request. `RequestSizeContentCheck`, `RequiredHeadersCheck`, `AuthenticationCheck`, `ReferrerCheck`, `CustomValidatorsCheck`, and `TimeWindowCheck` decide purely from per-route decorator settings, so guard-core can only skip them when it can enumerate the registered route configuration. `route_configs` comes from the middleware's `guard_decorator` attribute; when no decorator handler is registered it is `None`, `applies_to()` treats route configuration as unknown, and every route-driven check is kept, so this optimization can only be lost, never the protection those checks provide. See [Decorator Visibility Shapes the Pipeline](security-middleware.md) for how `SecurityMiddleware` resolves `guard_decorator` before this filtering runs.

Implementation Details
----------------------

Each check is self-contained and follows this pattern:

```python
from guard_core.core.checks.base import SecurityCheck


class ExampleCheck(SecurityCheck):
    check_name = "example_check"

    def __init__(self, middleware: "SecurityMiddleware"):
        self.middleware = middleware
        self.config = middleware.config
        self.logger = middleware.logger

    async def check(self, request: Request) -> Response | None:
        # Get context from request.state (set by RouteConfigCheck)
        client_ip = request.state.client_ip
        route_config = request.state.route_config

        # Perform check logic
        if should_block:
            return await self.create_error_response(403, "Check failed")

        return None  # Check passed
```

Helper Functions
----------------

**Location**: `guard_core/core/checks/helpers.py`

Common utilities shared across check implementations:

- `check_route_ip_access()` - IP whitelist/blacklist validation
- `check_user_agent_allowed()` - User agent validation
- `get_client_country()` - Country lookup
- Other shared validation logic

___

Module: guard_core/core/events/
--------------------------

**Purpose**: Event system for middleware actions and metrics collection

SecurityEventBus
----------------

Centralized event dispatching for security-related events.

**Location**: `guard_core/core/events/middleware_events.py`

**Key Methods**:

```python
class SecurityEventBus:
    async def send_middleware_event(
        self,
        event_type: str,
        request: Request,
        action_taken: str,
        reason: str,
        **kwargs,
    ) -> None:
        """Send middleware-specific events to agent."""
        ...

    async def send_https_violation_event(
        self, request: Request, route_config: RouteConfig | None
    ) -> None:
        """Send HTTPS violation event."""
        ...

    async def send_cloud_detection_events(
        self,
        request: Request,
        client_ip: str,
        cloud_providers: list[str],
        route_config: RouteConfig | None,
        cloud_handler: Any,
        passive_mode: bool,
    ) -> None:
        """Send cloud provider detection events."""
        ...
```

**Usage**: Sends events to optional monitoring agent for observability.

MetricsCollector
-----------------

Collects and reports request metrics.

**Location**: `guard_core/core/events/metrics.py`

**Key Methods**:

```python
class MetricsCollector:
    async def send_security_metric(
        self, metric_name: str, value: float, tags: dict[str, str] | None = None
    ) -> None:
        """Send individual security metric."""
        ...

    async def collect_request_metrics(
        self,
        request: Request,
        response: Response,
        response_time: float,
        client_ip: str,
    ) -> None:
        """Collect comprehensive request metrics."""
        ...
```

___

Module: guard_core/core/initialization/
----------------------------------

**Purpose**: Centralized handler initialization logic

HandlerInitializer
-------------------

Manages initialization of Redis, Agent, and other handlers.

**Location**: `guard_core/core/initialization/handler_initializer.py`

**Key Methods**:

```python
class HandlerInitializer:
    async def initialize_redis_handlers(self) -> None:
        """Initialize Redis for all handlers."""
        ...

    async def initialize_agent_for_handlers(self) -> None:
        """Initialize agent in all handlers."""
        ...

    async def initialize_agent_integrations(self) -> None:
        """Initialize agent and its integrations."""
        ...

    async def initialize_dynamic_rule_manager(self) -> None:
        """Initialize dynamic rule manager if configured."""
        ...
```

**Usage**: Called from `SecurityMiddleware.initialize()` to set up all handlers.

Shared-State Registry
---------------------

**Location**: `guard/_middleware_state.py`

A module-local registry keyed by `(id(config), id(decorator))` holds a `MiddlewareState` dataclass with the live `security_pipeline`, `composite_handler`, `event_bus`, `metrics_collector`, `response_factory`, `validator`, `bypass_handler`, `behavioral_processor`, `handler_initializer`, and `agent_handler`.

The lifespan helpers (`guard_lifespan`, `make_lifespan`) and the lazy-init fallback path both write to this registry after `SecurityMiddleware.initialize()` succeeds. A subsequent `SecurityMiddleware` instance adopts the registered components by reference via `_adopt_warm_state()` only when it resolves both the same `SecurityConfig` and the same decorator handler; otherwise it builds its own pipeline. The decorator is part of the key because the pipeline is derived from the registered per-route configuration, so two apps sharing one `SecurityConfig` but decorating different routes must not share a pipeline.

This is the mechanism that guarantees `composite_handler.start()` — which sets the OTEL/Logfire global tracer providers and starts the agent worker tasks — runs exactly once per config across the spawned-vs-live middleware instances Starlette produces when a lifespan is in use.

___

Module: guard_core/core/responses/
-----------------------------

**Purpose**: Response creation and processing

ErrorResponseFactory
---------------------

Centralized response creation, error handling, and header application.

**Location**: `guard_core/core/responses/factory.py`

**Key Methods**:

```python
class ErrorResponseFactory:
    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> Response:
        """Create standardized error response with custom message."""
        ...

    async def create_https_redirect(self, request: Request) -> Response:
        """Create HTTPS redirect response."""
        ...

    async def process_response(
        self,
        request: Request,
        response: Response,
        response_time: float,
        route_config: RouteConfig | None,
        process_behavioral_rules: Callable | None = None,
    ) -> Response:
        """Process response with metrics, headers, and behavioral rules."""
        ...
```

**Features**:

- Custom error message support
- Security header application
- CORS header handling
- Metrics collection
- Behavioral rule processing

ResponseContext
----------------

Dependency injection container for response factory.

**Location**: `guard_core/core/responses/context.py`

___

Module: guard_core/core/routing/
-------------------------

**Purpose**: Route configuration and decorator resolution

RouteConfigResolver
--------------------

Resolves route-specific security configuration from decorators.

**Location**: `guard_core/core/routing/resolver.py`

**Key Methods**:

```python
class RouteConfigResolver:
    def get_route_config(self, request: Request) -> RouteConfig | None:
        """Get route-specific security configuration."""
        ...

    def should_bypass_check(
        self, check_name: str, route_config: RouteConfig | None
    ) -> bool:
        """Check if security check should be bypassed."""
        ...

    def get_cloud_providers_to_check(
        self, route_config: RouteConfig | None
    ) -> list[str] | None:
        """Get cloud providers to check (route-specific or global)."""
        ...
```

**Usage**: Resolves decorator configurations for route-level security overrides.

RoutingContext
---------------

Dependency injection container for route resolver.

**Location**: `guard_core/core/routing/context.py`

___

Module: guard_core/core/validation/
-----------------------------

**Purpose**: Request validation utilities

RequestValidator
----------------

Provides request validation logic for HTTPS, proxies, time windows, and path exclusions.

**Location**: `guard_core/core/validation/validator.py`

**Key Methods**:

```python
class RequestValidator:
    def is_request_https(self, request: Request) -> bool:
        """Check if request uses HTTPS."""
        ...

    def is_trusted_proxy(self, client_ip: str) -> bool:
        """Validate if IP is a trusted proxy."""
        ...

    async def check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        """Validate time window restrictions."""
        ...

    def is_path_excluded(self, path: str) -> bool:
        """Check if path is excluded from security checks."""
        ...
```

ValidationContext
------------------

Dependency injection container for validator.

**Location**: `guard_core/core/validation/context.py`

___

Module: guard_core/core/bypass/
--------------------------

**Purpose**: Handle security bypass cases

BypassHandler
-------------

Handles passthrough cases and decorator-based security bypasses.

**Location**: `guard_core/core/bypass/handler.py`

**Key Methods**:

```python
class BypassHandler:
    async def handle_passthrough(
        self, request: Request, call_next: Callable
    ) -> Response | None:
        """Handle cases that should pass through immediately."""
        ...

    async def handle_security_bypass(
        self,
        request: Request,
        call_next: Callable,
        route_config: RouteConfig | None,
    ) -> Response | None:
        """Handle decorator-based security bypasses."""
        ...
```

**Features**:

- No client IP detection (passthrough)
- Excluded path handling
- Decorator bypass support
- Early exit optimization

BypassContext
--------------

Dependency injection container for bypass handler.

**Location**: `guard_core/core/bypass/context.py`

___

Module: guard_core/core/behavioral/
-----------------------------

**Purpose**: Behavioral rule processing

BehavioralProcessor
--------------------

Processes decorator-based behavioral rules for usage and return monitoring.

**Location**: `guard_core/core/behavioral/processor.py`

**Key Methods**:

```python
class BehavioralProcessor:
    async def process_usage_rules(
        self, request: Request, client_ip: str, route_config: RouteConfig
    ) -> None:
        """Process behavioral usage rules (pre-request)."""
        ...

    async def process_return_rules(
        self,
        request: Request,
        response: Response,
        client_ip: str,
        route_config: RouteConfig,
    ) -> None:
        """Process behavioral return rules (post-request)."""
        ...

    def get_endpoint_id(self, request: Request) -> str:
        """Generate unique endpoint identifier."""
        ...
```

BehavioralContext
------------------

Dependency injection container for behavioral processor.

**Location**: `guard_core/core/behavioral/context.py`

___

Dependency Injection Pattern
----------------------------

All core modules use **Context objects** for clean dependency injection:

```python
# Example: ResponseContext
@dataclass
class ResponseContext:
    config: SecurityConfig
    logger: logging.Logger
    metrics_collector: MetricsCollector
    agent_handler: Any
    guard_decorator: BaseSecurityDecorator | None
```

**Benefits**:

- Explicit dependencies
- Easy testing with mocks
- Prevents tight coupling
- Type-safe dependency passing

___

Adding New Security Checks
--------------------------

To add a custom security check:

1. Create Implementation

**File**: `guard_core/core/checks/implementations/my_custom_check.py`

```python
from fastapi import Request, Response
from guard_core.core.checks.base import SecurityCheck


class MyCustomCheck(SecurityCheck):
    """Description of what this check does."""

    check_name = "my_custom_check"

    def __init__(self, middleware: "SecurityMiddleware"):
        self.middleware = middleware
        self.config = middleware.config
        self.logger = middleware.logger

    async def check(self, request: Request) -> Response | None:
        # Get context from request.state
        client_ip = request.state.client_ip
        route_config = request.state.route_config

        # Your check logic
        if condition_fails:
            self.logger.warning(f"Check failed for {client_ip}")
            return await self.create_error_response(403, "Custom check failed")

        return None  # Check passed
```

2. Register in Pipeline

**File**: `guard/middleware.py` in `_build_security_pipeline()` method

```python
from guard_core.core.checks import build_default_pipeline
from guard_core.core.checks.implementations.my_custom_check import MyCustomCheck


def _build_security_pipeline(self) -> None:
    pipeline = build_default_pipeline(self)
    pipeline.add_check(MyCustomCheck(self))
    self.security_pipeline = pipeline
```

3. Export (Optional)

**File**: `guard_core/core/checks/__init__.py`

```python
from guard_core.core.checks.implementations.my_custom_check import MyCustomCheck

__all__ = [
    # ... existing exports
    "MyCustomCheck",
]
```

4. Test

```python
import pytest
from guard_core.core.checks.implementations.my_custom_check import MyCustomCheck


@pytest.mark.asyncio
async def test_my_custom_check(test_middleware, test_request):
    check = MyCustomCheck(test_middleware)
    response = await check.check(test_request)
    assert response is None  # or assert response.status_code == 403
```

___

Testing Core Modules
--------------------

Each module is independently testable:

```python
# Test a specific check
from guard_core.core.checks.implementations import IpSecurityCheck


async def test_ip_security():
    middleware = create_test_middleware()
    check = IpSecurityCheck(middleware)

    request = create_test_request(client_ip="10.0.0.1")
    response = await check.check(request)

    assert response is None  # IP allowed
```

```python
# Test the pipeline
from guard_core.core.checks import SecurityCheckPipeline


async def test_pipeline():
    checks = [Check1(middleware), Check2(middleware)]
    pipeline = SecurityCheckPipeline(checks)

    response = await pipeline.execute(request)
    assert response is None  # All checks passed
```

___

Performance Considerations
--------------------------

Pipeline Optimization
----------------------

- **Early Termination**: Pipeline stops at first blocking check
- **Conditional Checks**: Pipeline construction skips checks that configuration and decorator-registered routes can never trigger, so they are never built rather than merely returning early (see Execution Order above)
- **Cached Results**: Some checks cache results per request

Modular Benefits
----------------

- **Independent Caching**: Each module can cache independently
- **Targeted Optimization**: Identify and optimize specific bottlenecks
- **Profiling**: Easy to profile individual checks

___

Migration from Monolithic Architecture
--------------------------------------

The modular architecture provides several improvements over the original monolithic `middleware.py`:

| Aspect | Old (Monolithic) | New (Modular) |
|--------|------------------|---------------|
| **File Size** | 2,087 LOC | 471 LOC + 9 modules |
| **Maintainability** | MI 0.00 (C) | MI 54.51 (A) |
| **Complexity** | ~15 avg | 2.35 avg |
| **Testability** | Hard (coupled) | Easy (isolated) |
| **Extensibility** | Difficult | Simple |

**For Contributors**: All new features should follow the modular pattern.

___

References
----------

- **Full Architecture Documentation**: See `ARCHITECTURE_CHANGES.md` in project root
- **Public API Documentation**: See other API reference pages
- **Task Documentation**: `.claude/tasks/COMPLETED/002-*` and `003-*`
- **Code Quality Metrics**: All core modules achieve MI 56-82 (Rank A)

___

See Also
--------

- [SecurityMiddleware](security-middleware.md) - Main middleware documentation
- [API Overview](overview.md) - Complete API reference
- [Decorators](decorators.md) - Route-level security decorators
