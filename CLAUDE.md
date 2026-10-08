# AGENTS.md
Guidance for AI agents (including Claude Code) working in this repository.

## Project Overview

FastAPI Guard is a production-ready security library for FastAPI applications that provides:

- IP control and rate limiting
- Request logging and monitoring
- Penetration attempt detection
- Security headers management
- Redis-based distributed caching

- **PyPI Package**: `fastapi-guard`
- **Import Name**: `guard`
- **Python Support**: 3.10, 3.11, 3.12, 3.13, 3.14
- **Package Manager**: uv (modern Python package manager)
- **Build System**: Docker + Make

## Ecosystem Position

As of v5.0.0, fastapi-guard is a **thin adapter** over [guard-core](https://github.com/Guard-Core/guard-core). All security logic (models, handlers, decorators, detection engine, protocols, utilities) lives in the `guard_core` package. This repo contains only the FastAPI/Starlette integration layer.

```
guard-core (engine, PyPI dependency)   <- all security logic
└── fastapi-guard (this repo)          <- ASGI middleware adapter for FastAPI/Starlette
    ├── flaskapi-guard                 <- sibling adapter (Flask extension, sync mirror)
    ├── djapi-guard                    <- sibling adapter (Django middleware, sync mirror)
    └── tornadoapi-guard               <- sibling adapter (Tornado handler/middleware)
```

Because FastAPI/Starlette is async, this adapter imports `guard_core.*` directly (the sync adapter siblings import the unasync-generated `guard_core.sync.*` mirror instead).

### Package Components

- **`guard/__init__.py`** - Re-exports 20+ items from `guard_core` so users can `from guard import SecurityConfig, SecurityDecorator, ...` without knowing about guard-core. Also exports `SecurityMiddleware` from `guard.middleware`.
- **`guard/middleware.py`** - `SecurityMiddleware` extends Starlette's `BaseHTTPMiddleware`. It wraps Starlette `Request`/`Response` objects via adapters, delegates all security checks to guard-core's pipeline, and orchestrates initialization, event dispatch, metrics, and response processing using guard-core modules (`core.checks`, `core.events`, `core.initialization`, `core.responses`, `core.routing`, `core.validation`, `core.bypass`, `core.behavioral`).
- **`guard/adapters.py`** - Protocol adapters that bridge Starlette types to guard-core's framework-agnostic protocols: `StarletteGuardRequest` (adapts `starlette.requests.Request` to `GuardRequest`), `StarletteGuardResponse` (adapts `starlette.responses.Response` to `GuardResponse`), `StarletteResponseFactory` (creates response adapters), and the lifecycle helpers `wrap_call_next()` / `unwrap_response()`.
- **`guard/lifespan.py`** - `guard_lifespan`, `make_lifespan`, and `guard_startup` warm guard-core's shared-state registry at app startup so initialization does not happen on the first request.
- **`guard/_middleware_state.py`** - `MiddlewareState` registry keyed on the `SecurityConfig` instance and the resolved decorator handler, so two middleware instances sharing one config only share a pipeline when they resolve the same decorator handler.
- **`guard/_decorator_adoption.py`** - Resolves and adopts the app's registered `guard_decorator` (`resolve_app_state_decorator`, `adopt_app_state_decorator`) so the pipeline can be derived from the registered route config.
- **`guard/status.py`** - `add_status_route` helper exposing a guard status endpoint.
- **`guard/websocket.py`** - WebSocket support (`WebSocketCloseReason`, a `_WebSocketGuardRequest` adapter for WebSocket connections).

### Public API

All public imports go through `guard`:

```python
from guard.middleware import SecurityMiddleware
from guard import SecurityConfig, SecurityDecorator, RouteConfig
from guard import IPBanManager, RateLimitManager, RedisManager
from guard import GeoIPHandler, RedisHandlerProtocol
```

## Boundary Rules

- **This repo MUST NOT** contain security logic (checks, handlers, models, detection patterns). Those belong in [guard-core](https://github.com/Guard-Core/guard-core). A change that looks like a security fix belongs upstream in guard-core, not here.
- **This repo MUST** wire Starlette/FastAPI native types to guard-core's `GuardRequest`, `GuardResponse`, and `GuardResponseFactory` protocols via `guard/adapters.py`.
- **This repo MUST** keep `SecurityMiddleware` as a thin orchestrator that delegates to `SecurityCheckPipeline`; do not fork or reimplement pipeline behavior.
- **This repo MUST** re-export new guard-core public surface from `guard/__init__.py` when it becomes part of the adapter's user-facing API.
- This repo should only change when:
  - The Starlette/FastAPI adapter layer needs updates
  - New guard-core exports need to be re-exported from `guard/__init__.py`
  - FastAPI-specific middleware orchestration changes

## Quick Start

```bash
# Install dependencies with uv
make install-dev

# Run tests locally
make local-test

# Start example application
make start-example

# Run linting and formatting
make fix
```

## Development Commands

### Package Management (uv)

- `make install` - Install core dependencies
- `make install-dev` - Install with dev dependencies
- `make lock` - Update lock file
- `make upgrade` - Upgrade lock dependencies and install
- `uv sync` - Sync dependencies from lock file
- `uv sync --extra dev` - Sync with dev extras
- `uv run <command>` - Run command in virtual environment

### Testing

- `make test` - Run tests in Docker (Python 3.10)
- `make test-all` - Test all Python versions (3.10-3.14)
- `make test-3.11` - Test specific Python version
- `make local-test` - Run tests locally with uv
- `make stress-test` - Run standard stress test
- `make high-load-stress-test` - Run high-load stress test
- `make live-smoke` - Run the live smoke suite against a real stack

### Code Quality

- `make lint` - Run all linters in Docker (ruff, mypy)
- `make fix` - Auto-fix formatting issues with ruff
- `make vulture` - Find dead code
- `make bandit` - Security scan
- `make safety` - Check dependency vulnerabilities
- `make pip-audit` - Audit dependencies
- `make radon` - Analyze code complexity
- `make xenon` - Check complexity thresholds
- `make deptry` - Analyze dependencies
- `make semgrep` - Static analysis
- `make security` - Run all security checks (bandit, safety, pip-audit)
- `make quality` - Run all quality checks (lint, vulture, radon, xenon)
- `make check-all` - Run everything (lint, security, quality, analysis)
- `uv run ruff check guard/ tests/` - Check with ruff
- `uv run ruff format guard/ tests/` - Format code
- `uv run mypy guard/` - Type checking

### Documentation

- `make serve-docs` - Serve MkDocs locally
- `make lint-docs` - Lint markdown files
- `make fix-docs` - Fix markdown issues

### Docker Operations

- `make start-example` - Start example app with Docker
- `make run-example` - Build and run example
- `make stop` - Stop all containers
- `make restart` - Restart services
- `make prune` - Clean Docker resources
- `make clean` - Clean Python cache files

Environment variables:

- `PYTHON_VERSION` - Python version (3.10-3.14)
- `REDIS_URL` - Redis connection string
- `REDIS_PREFIX` - Key prefix for Redis
- `IPINFO_TOKEN` - IPInfo API token

Services: `fastapi-guard-example` (example application), `fastapi-guard` (test runner), `redis` (cache).

### Version Management

- `make bump-version VERSION=x.y.z` - Bump package version

## Project Structure

```text
fastapi-guard/
├── guard/                     # Adapter package (thin layer over guard-core)
│   ├── __init__.py            # Re-exports 20+ items from guard_core + SecurityMiddleware
│   ├── middleware.py          # FastAPI/Starlette SecurityMiddleware adapter
│   ├── adapters.py            # Starlette request/response protocol adapters
│   ├── lifespan.py            # guard_lifespan / make_lifespan / guard_startup
│   ├── _middleware_state.py   # MiddlewareState registry (config + decorator keyed)
│   ├── _decorator_adoption.py # resolve/adopt the app's registered guard_decorator
│   ├── status.py              # add_status_route helper
│   ├── websocket.py           # WebSocket support
│   ├── .agents/skills/fastapi-guard/  # Package skill (SKILL.md + references)
│   └── py.typed               # PEP 561 marker
├── tests/                 # Test suite
├── examples/              # Example implementations
├── docs/                  # MkDocs documentation
├── Makefile              # Build automation
├── compose.yml           # Docker Compose config
├── Dockerfile            # Docker image definition
├── pyproject.toml        # Project metadata & config
├── uv.lock              # Locked dependencies
├── setup.py             # Minimal (package discovery only, no version)
└── .pre-commit-config.yaml  # Pre-commit hooks
```

### Configuration Files

- **pyproject.toml** - Project metadata and dependencies; tool configurations for ruff, mypy, pytest; Python 3.10+ requirement
- **uv.lock** - Locked dependency versions for reproducible builds, updated with `make lock` or `uv lock`
- **compose.yml / Dockerfile** - Multi-version Python support (3.10-3.14), Redis service for testing, volume mounts for development
- **.pre-commit-config.yaml** - ruff format, ruff check, mypy

## Technology Stack

### Core Dependencies

- **FastAPI** - Modern async web framework
- **guard-core** - Framework-agnostic security engine (all security logic)
- **Starlette** - ASGI toolkit (FastAPI's foundation)
- **uvicorn** - ASGI server

### Development Tools

- **uv** - Fast Python package manager
- **pytest** - Testing framework
- **pytest-asyncio** - Async test support
- **pytest-cov** - Coverage reporting
- **pytest-mock** - Mock fixtures
- **ruff** - Fast Python linter/formatter
- **mypy** - Static type checker
- **vulture** - Dead code detection
- **bandit** - Security linter
- **radon/xenon** - Complexity analysis
- **deptry** - Dependency analysis
- **semgrep** - Static analysis
- **pre-commit** - Git hooks
- **mkdocs** - Documentation generator
- **mkdocs-material** - MkDocs theme
- **pymarkdownlnt** - Markdown linter

## Testing Guidelines

### Running Tests

```bash
# Local testing with coverage
make local-test

# Docker testing (default Python 3.10)
make test

# Test all Python versions
make test-all

# Specific Python version
make test-3.12
```

### Test Configuration (pyproject.toml)

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
python_files = ["test_*.py"]
addopts = "--cov=guard --cov-report=term-missing"
```

### Run Specific Tests

```bash
# Run specific test file
REDIS_URL=redis://localhost:6379 uv run pytest tests/test_security_headers/test_middleware_coverage.py -v

# Run with pattern matching
REDIS_URL=redis://localhost:6379 uv run pytest -k "security_headers" -v
```

## Code Quality Standards

### Ruff Configuration

- Target Python 3.10+
- Selected rules: E, F, UP, B, I
- Auto-fixable issues

### MyPy Configuration

- Strict type checking enabled
- No implicit Optional
- Warn on unused configs
- Check untyped definitions

### Pre-commit Workflow

1. Automatic formatting with ruff
2. Linting checks
3. Type checking with mypy
4. All run via `uv run` commands

## Best Practices

1. **Always use uv** for package management
2. **Run tests** before committing
3. **Use Make commands** for consistency
4. **Test multiple Python versions** for compatibility
5. **Keep dependencies updated** with `make upgrade`
6. **Use type hints** and run mypy
7. **Follow ruff** formatting standards
8. **Document changes** in appropriate docs/

### Security Considerations

- This is a security library - all code must be defensive
- Validate all inputs with Pydantic
- Use Redis for distributed rate limiting
- Implement proper error handling
- Log security events appropriately
- Never expose sensitive data in logs

## Related Projects

- **guard-core** - Framework-agnostic security engine (the engine this adapter wraps): <https://github.com/Guard-Core/guard-core>
- **flaskapi-guard** - Flask extension adapter (sync mirror): <https://github.com/Guard-Core/flaskapi-guard>
- **djapi-guard** - Django middleware adapter (sync mirror): <https://github.com/Guard-Core/djapi-guard>
- **tornadoapi-guard** - Tornado handler/middleware adapter: <https://github.com/Guard-Core/tornadoapi-guard>
- **guard-agent** - Telemetry and monitoring agent: <https://github.com/Guard-Core/guard-agent>
- **guard-core-mcp** - MCP server for config validation and docs search: <https://github.com/Guard-Core/guard-core-mcp>
- **guard-core-app** - SaaS platform (API, dashboard, playground): <https://github.com/Guard-Core/guard-core-app>
