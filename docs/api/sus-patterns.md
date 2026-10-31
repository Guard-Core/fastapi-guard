---

title: SusPatternsManager API - FastAPI Guard
description: API documentation for FastAPI Guard's suspicious pattern detection and management system
keywords: security patterns, threat detection, pattern management, security rules api
---

SusPatternsManager
==================

The `SusPatternsManager` class manages suspicious patterns for security threat detection using a singleton pattern with enhanced detection capabilities.

___

Class Definition
----------------

```python
class SusPatternsManager:
    """
    Singleton pattern manager with enhanced detection capabilities.

    Manages both default patterns (loaded from YAML files) and custom patterns,
    with optional detection engine components for advanced threat analysis.
    """
```

___

Pattern Management Methods
--------------------------

add_pattern
-----------

```python
@classmethod
async def add_pattern(cls, pattern: str, custom: bool = False) -> None:
    """
    Add a new pattern to the detection system.

    Args:
        pattern: Regular expression pattern to add
        custom: Whether this is a custom pattern (default: False)

    Note:
        - Custom patterns are stored separately and persist across restarts if Redis is enabled
        - Patterns are compiled and validated before being added
    """
```

remove_pattern
--------------

```python
@classmethod
async def remove_pattern(cls, pattern: str, custom: bool = False) -> bool:
    """
    Remove a pattern from the detection system.

    Args:
        pattern: Pattern to remove
        custom: Whether to remove from custom patterns

    Returns:
        bool: True if pattern was successfully removed, False otherwise
    """
```

clear_custom_patterns
---------------------

There is no single call that clears the custom patterns. Remove each one with `remove_pattern()`:

```python
for pattern in await sus_patterns_handler.get_custom_patterns():
    await sus_patterns_handler.remove_pattern(pattern, custom=True)
```

The default patterns come from the built-in pattern table and are not affected.

Pattern Retrieval Methods
-------------------------

```python
@classmethod
async def get_default_patterns(cls) -> list[str]:
    """Get only the default patterns loaded from YAML files."""


@classmethod
async def get_custom_patterns(cls) -> list[str]:
    """Get only the custom patterns added at runtime."""


@classmethod
async def get_all_patterns(cls) -> list[str]:
    """Get all registered patterns (default + custom)."""


@classmethod
async def get_default_compiled_patterns(
    cls,
) -> list[tuple[re.Pattern, frozenset[str], str]]:
    """Default compiled patterns with their contexts and category label."""


@classmethod
async def get_custom_compiled_patterns(
    cls,
) -> list[tuple[re.Pattern, frozenset[str], str]]:
    """Custom compiled patterns with their contexts and category label."""


@classmethod
async def get_all_compiled_patterns(
    cls,
) -> list[tuple[re.Pattern, frozenset[str], str]]:
    """
    Get all compiled regex patterns with their applicable contexts and category.

    Returns:
        List of (compiled_pattern, context_set, category) tuples.
        Context set contains applicable input sources:
        "query_param", "url_path", "header", "request_body", "unknown".
        Category is the threat-class label (e.g. "xss", "sqli",
        "dir_traversal", "ssrf", "xml", "recon", "sensitive_file",
        "ldap", "nosql", "custom").
    """
```

> Custom patterns added via `add_pattern(..., custom=True)` always carry the literal category label `"custom"` and run regardless of `detection_enabled_categories` filtering on `SecurityConfig` or per-route `RouteConfig`.

___

Context-Aware Filtering
------------------------

Patterns are tagged with the input contexts where they are applicable, reducing false positives by only matching patterns against relevant input sources.

**Context Types:**

| Context | Description |
|---------|-------------|
| `query_param` | URL query string parameters |
| `url_path` | URL path segments |
| `header` | HTTP request headers |
| `request_body` | Request body content (JSON, form data) |
| `unknown` | Unidentified source (all patterns apply) |

**Filtering Rules:**

- When context is `unknown` or `request_body`, all patterns are evaluated
- For specific contexts (`query_param`, `url_path`, `header`), only patterns tagged for that context are checked
- Custom patterns added via `add_pattern()` always apply to all contexts

**Example:** A SQL injection pattern tagged for `query_param` and `request_body` will fire on `?id=1 OR 1=1` but not on a URL path like `/api/union/select`.

**Context Definitions by Attack Type:**

- **XSS**: `query_param`, `header`, `request_body`
- **SQL Injection**: `query_param`, `request_body`
- **Directory/Path Traversal**: `url_path`, `query_param`, `request_body`
- **Command Injection**: `query_param`, `request_body`
- **File Inclusion**: `url_path`, `query_param`, `request_body`
- **XXE/XML**: `header`, `request_body`
- **SSRF**: `query_param`, `request_body`
- **Sensitive File Probing**: `url_path`, `request_body`
- **CMS Probing**: `url_path`, `request_body`

___

Detection Methods
-----------------

detect (Enhanced Detection)
---------------------------

```python
async def detect(
    self,
    content: str,
    ip_address: str,
    context: str = "unknown",
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """
    Perform comprehensive threat detection with detection engine.

    Args:
        content: Content to analyze
        ip_address: IP address of the request
        context: Where content came from (e.g., "query_param", "body")
        correlation_id: Optional ID for request correlation

    Returns:
        Comprehensive detection results including:
        - is_threat: Whether a threat was detected
        - threat_score: Score from 0.0 to 1.0
        - threats: List of detected threats with details
        - execution metrics and context
    """
```

detect_pattern_match (Legacy)
-----------------------------

```python
async def detect_pattern_match(
    self,
    content: str,
    ip_address: str,
    context: str = "unknown",
    correlation_id: str | None = None,
) -> tuple[bool, str | None]:
    """
    Legacy detection method for backward compatibility.

    Returns:
        Tuple of (pattern_detected, matched_pattern_string)
    """
```

___

Performance and Monitoring
--------------------------

get_performance_stats
---------------------

```python
@classmethod
async def get_performance_stats(cls) -> dict[str, Any] | None:
    """
    Get comprehensive performance statistics.

    Returns:
        Dictionary containing:
        - slow_patterns: Patterns exceeding slow threshold
        - problematic_patterns: Patterns with timeouts or anomalies
        - summary: Overall performance metrics

    Returns None if performance monitoring is not configured.
    """
```

get_component_status
--------------------

```python
@classmethod
async def get_component_status(cls) -> dict[str, bool]:
    """
    Check which detection engine components are active.

    Returns:
        Dictionary with component status:
        - compiler: Whether PatternCompiler is active
        - preprocessor: Whether ContentPreprocessor is active
        - semantic_analyzer: Whether SemanticAnalyzer is active
        - performance_monitor: Whether PerformanceMonitor is active
    """
```

configure_semantic_threshold
-----------------------------

```python
async def configure_semantic_threshold(self, threshold: float) -> None:
    """
    Dynamically adjust semantic analysis threshold.

    Args:
        threshold: New threshold value (0.0 to 1.0)
                  0 = disabled, higher values = stricter detection
    """
```

___

Detection Result Structure
--------------------------

The `detect()` method returns a comprehensive result dictionary:

```python
{
    "is_threat": bool,  # True if any threat detected
    "threat_score": float,  # 0.0-1.0, highest threat score
    "threats": [  # List of detected threats
        {
            "type": "regex",  # Detection type
            "pattern": str,  # Pattern that matched
            "execution_time": float,  # Time to execute pattern
        },
        {
            "type": "semantic",  # Heuristic detection
            "score": float,  # Threat score
            "attack_types": dict,  # Attack type probabilities
            "confidence": str,  # low/medium/high
        },
    ],
    "context": str,  # Where content came from
    "original_length": int,  # Original content length
    "processed_length": int,  # After preprocessing
    "execution_time": float,  # Total detection time
    "detection_method": str,  # "enhanced" or "legacy"
    "timeouts": list[str],  # Patterns that timed out
    "correlation_id": str | None,  # Request correlation ID
}
```

___

Usage Examples
--------------

Basic Pattern Management
------------------------

```python
from guard import sus_patterns_handler

# Add custom pattern
await sus_patterns_handler.add_pattern(r"(?i)malicious_pattern", custom=True)

# Remove pattern
success = await sus_patterns_handler.remove_pattern(
    r"(?i)malicious_pattern", custom=True
)

# Get all patterns
patterns = await sus_patterns_handler.get_all_patterns()
```

Enhanced Threat Detection
-------------------------

```python
# Perform detection with full context
result = await sus_patterns_handler.detect(
    content="SELECT * FROM users WHERE id=1 OR 1=1",
    ip_address="192.168.1.100",
    context="query_param:search",
    correlation_id="req-123",
)

if result["is_threat"]:
    print(f"Threat score: {result['threat_score']}")

    for threat in result["threats"]:
        if threat["type"] == "regex":
            print(f"Pattern matched: {threat['pattern']}")
        elif threat["type"] == "semantic":
            print(f"Attack type: {threat.get('attack_types')}")
```

Performance Monitoring
----------------------

```python
# Get performance statistics
stats = await sus_patterns_handler.get_performance_stats()
if stats:
    print(f"Average execution time: {stats['summary']['avg_execution_time']}")
    print(f"Timeout rate: {stats['summary']['timeout_rate']}")

    # Check for slow patterns
    for pattern in stats["slow_patterns"]:
        print(f"Slow pattern: {pattern['pattern']}")
        print(f"Average time: {pattern['avg_execution_time']}")

# Check component status
status = await sus_patterns_handler.get_component_status()
print(f"Semantic analyzer active: {status['semantic_analyzer']}")
print(f"Performance monitor active: {status['performance_monitor']}")
```

Configuration Adjustment
------------------------

```python
# Adjust semantic threshold dynamically
await sus_patterns_handler.configure_semantic_threshold(0.8)

# Disable semantic analysis
await sus_patterns_handler.configure_semantic_threshold(0.0)
```

___

Pattern Storage
---------------

Default Patterns
----------------

Default patterns are loaded from YAML files in the package:

- Common attack patterns
- SQL injection patterns
- XSS patterns
- Path traversal patterns
- Command injection patterns

Custom Patterns
---------------

Custom patterns are:

- Added at runtime via `add_pattern()`
- Stored in memory and optionally in Redis
- Preserved across restarts when Redis is enabled
- Managed separately from default patterns

Redis Integration
-----------------

When Redis is enabled:

```python
# Patterns are automatically synced to Redis
await sus_patterns_handler.add_pattern(r"custom.*", custom=True)

# Retrieved on startup
patterns = await redis_handler.get_key("patterns", "custom_list")
```

___

Best Practices
--------------

1. **Pattern Design**: Keep patterns specific to avoid false positives
2. **Performance**: Monitor pattern execution times regularly
3. **Semantic Threshold**: Start with default (0.7) and adjust based on false positives
4. **Custom Patterns**: Test thoroughly before adding to production
5. **Monitoring**: Use `get_performance_stats()` to identify problematic patterns

___

Error Handling
--------------

The manager handles various error conditions gracefully:

- Invalid regex patterns are logged and skipped
- Component initialization failures fall back to basic detection
- Pattern timeouts are logged and don't stop detection
- Redis connection failures don't prevent operation

___

Thread Safety
-------------

The SusPatternsManager uses:

- Thread-safe singleton pattern
- Async-safe operations
- Thread pool for pattern execution
- Proper locking for pattern modifications
