---

title: Penetration Detection - FastAPI Guard
description: Detect and prevent common attack patterns including SQL injection, XSS, and other security threats
keywords: penetration detection, attack prevention, security patterns, threat detection
---

Penetration Detection
=====================

FastAPI Guard includes sophisticated penetration attempt detection to identify and block malicious requests.

___

Basic Configuration
-------------------

Enable penetration detection with the enhanced Detection Engine:

```python
config = SecurityConfig(
    # Core detection settings
    enable_penetration_detection=True,
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    auto_ban_duration=3600,  # Ban duration in seconds
    # Detection Engine configuration
    detection_compiler_timeout=2.0,  # Pattern matching timeout
    detection_max_content_length=10000,  # Max content to analyze
    detection_preserve_attack_patterns=True,  # Preserve attacks during truncation
    detection_semantic_threshold=0.7,  # Semantic detection threshold (0.0-1.0)
    # Performance monitoring
    detection_anomaly_threshold=3.0,  # Standard deviations for anomaly
    detection_slow_pattern_threshold=0.1,  # Slow pattern threshold (seconds)
    detection_monitor_history_size=1000,  # Metrics history size
    detection_max_tracked_patterns=1000,  # Max patterns to track
)
```

___

Detection Patterns
------------------

The system checks for various attack patterns including:

- SQL Injection attempts
- XSS (Cross-Site Scripting)
- Command Injection
- Path Traversal
- Template Injection
- HTTP Response Splitting
- LDAP Injection
- XML Injection
- NoSQL Injection
- File Upload attacks

___

Excluding Parameters, Headers and Body Fields
---------------------------------------------

Every query parameter, header and JSON body field is scanned against every pattern. Some values look like attacks by design: an OAuth `redirect_uri` on `/authorize` is a full URL, and for native and MCP clients it is a loopback one (`http://127.0.0.1:<port>/callback`, `http://localhost:<port>/callback`), which the `ssrf` category matches. Rather than moving the whole path into `exclude_paths` and losing the other checks with it, exclude just that field:

```python
config = SecurityConfig(
    enable_penetration_detection=True,
    # OAuth redirect targets are validated against the registered client, not fetched
    excluded_detection_params={"redirect_uri"},
)
```

The same exists for headers and JSON body keys (`excluded_detection_headers`, `excluded_detection_body_fields`); names are matched case-insensitively, and body keys at any nesting depth. Headers carrying URLs are the usual header case: `referer` and `origin` hold full URLs and can trip the `ssrf` category on endpoints that legitimately receive them.

```python
config = SecurityConfig(
    enable_penetration_detection=True,
    excluded_detection_headers={"referer", "origin"},
)
```

Excluding a name stops the semantic analysis of that value; the pattern-based checks still run against it, so the header is not fully silenced. To limit the exclusion to one route, use the decorator instead of the global setting:

```python
from guard import SecurityDecorator

guard_deco = SecurityDecorator(config)
# the middleware reads route decorators from here
app.state.guard_decorator = guard_deco


@guard_deco.detection_exclusion(params={"redirect_uri", "post_logout_redirect_uri"})
@app.get("/oauth/authorize")
async def authorize(): ...
```

Everything else on the request is still scanned.

___

Enhanced Detection Features
---------------------------

The new Detection Engine provides advanced threat detection capabilities:

Multi-layered Detection
-----------------------

- **Pattern Matching**: Regex-based detection with timeout protection
- **Semantic Analysis**: AI-powered detection of obfuscated attacks
- **Performance Monitoring**: Real-time tracking of pattern effectiveness

Comprehensive Results
---------------------

The detection engine returns detailed information about threats:

```python
from guard import sus_patterns_handler

# Direct detection with rich results
result = await sus_patterns_handler.detect(
    content="SELECT * FROM users WHERE id=1 OR 1=1",
    ip_address="192.168.1.100",
    context="query_param",
)

if result["is_threat"]:
    print(f"Threat Score: {result['threat_score']}")  # 0.0 to 1.0
    for threat in result["threats"]:
        if threat["type"] == "regex":
            print(f"Pattern: {threat['pattern']}")
        elif threat["type"] == "semantic":
            print(f"Attack Type: {threat['attack_type']}")
            print(f"Probability: {threat['probability']}")
```

Performance Analytics
---------------------

Monitor and optimize detection performance:

```python
# Get performance statistics
stats = await sus_patterns_handler.get_performance_stats()
print(f"Slow patterns: {stats['slow_patterns']}")
print(f"Problematic patterns: {stats['problematic_patterns']}")
```

Custom Detection Logic
----------------------

You can use the penetration detection directly in your routes:

```python
from guard_core.utils import detect_penetration_attempt


@app.post("/api/data")
async def submit_data(request: Request):
    # Legacy method (still supported)
    is_suspicious, trigger_info = await detect_penetration_attempt(request)
    if is_suspicious:
        return JSONResponse(
            status_code=400,
            content={"error": f"Suspicious activity detected: {trigger_info}"},
        )
    # Process legitimate request
    return {"status": "success"}
```

For more control, use the enhanced detection API:

```python
from guard import sus_patterns_handler


@app.post("/api/secure")
async def secure_endpoint(request: Request, data: dict):
    # Check request body with enhanced detection
    result = await sus_patterns_handler.detect(
        content=json.dumps(data), ip_address=request.client.host, context="request_body"
    )

    if result["is_threat"] and result["threat_score"] > 0.8:
        # High-confidence threat detected
        threat_types = [t.get("attack_type", t["type"]) for t in result["threats"]]
        return JSONResponse(
            status_code=403,
            content={"error": f"Threat detected: {', '.join(threat_types)}"},
        )

    # Process request
    return {"status": "success"}
```

___

Logging Suspicious Activity
----------------------------

Configure logging for suspicious activities:

```python
config = SecurityConfig(custom_log_file="security.log", log_level="WARNING")
```

Example log output:

```text
2024-01-20 10:15:23 - WARNING - Suspicious activity detected from 192.168.1.1: POST /api/data - Reason: SQL injection attempt
```

___

Passive Mode
------------

When `passive_mode` is enabled, FastAPI Guard will:

1. Detect potential penetration attempts (work as usual)
2. Log them with detailed information about what triggered the detection
3. Allow the requests to proceed without blocking

This helps you understand your traffic patterns and fine-tune your security settings before enforcing blocks that might affect legitimate users.

___

How to Use Passive Mode
-----------------------

```python
from fastapi import FastAPI
from guard import SecurityMiddleware, SecurityConfig

app = FastAPI()

# Create a configuration with passive mode enabled
config = SecurityConfig(
    enable_penetration_detection=True,  # True by default
    passive_mode=True,  # Enable passive mode
)

# Add the middleware to your application
app.add_middleware(SecurityMiddleware, config=config)
```

___

Checking Logs
-------------

When using passive mode, watch your logs for entries starting with "[PASSIVE MODE]". These entries provide detailed information about what triggered the detection, including:

- The client's IP address
- The HTTP method and URL
- The specific pattern that was matched
- Which part of the request triggered the detection (query parameter, body, header, etc.)
- Threat score and attack type (for semantic detection)
- Performance metrics and timeouts

___

Advanced Configuration
----------------------

Pattern Management
------------------

Add or remove custom patterns:

```python
from guard import sus_patterns_handler

# Add custom pattern
await sus_patterns_handler.add_pattern(
    r"(?i)exec\s*\(\s*['\"].*['\"]\s*\)",  # Detect exec() calls
    custom=True,
)

# Remove pattern
await sus_patterns_handler.remove_pattern(
    r"(?i)exec\s*\(\s*['\"].*['\"]\s*\)", custom=True
)

# Get all patterns
patterns = await sus_patterns_handler.get_all_patterns()
```

Semantic Threshold Tuning
-------------------------

Adjust the semantic detection sensitivity:

```python
# More strict (fewer false positives, might miss some attacks)
await sus_patterns_handler.configure_semantic_threshold(0.9)

# More lenient (catch more attacks, might have false positives)
await sus_patterns_handler.configure_semantic_threshold(0.5)
```

Component Status
----------------

Check which detection components are active:

```python
status = await sus_patterns_handler.get_component_status()
# Returns: {
#     "compiler": True,
#     "preprocessor": True,
#     "semantic_analyzer": True,
#     "performance_monitor": True
# }
```

___

Integration with FastAPI Guard Agent

When the Guard Agent is enabled, the Detection Engine automatically:

- Sends detailed threat detection events
- Reports pattern performance metrics
- Tracks pattern effectiveness
- Shares threat intelligence

Configure with:

```python
config = SecurityConfig(
    enable_agent=True,
    agent_api_key="your-api-key",
    agent_enable_events=True,
    agent_enable_metrics=True,
    # ... other settings
)
```

___

Best Practices

1. **Start with Passive Mode**: Test detection patterns without blocking traffic
2. **Monitor Performance**: Review slow patterns regularly
3. **Tune Thresholds**: Adjust based on your false positive tolerance
4. **Update Patterns**: Keep patterns updated with latest attack vectors
5. **Use Correlation IDs**: Track related detections across requests

___

Further Reading

- [Detection Engine Overview](detection-engine/overview.md)
- [Detection Engine Architecture](detection-engine/architecture.md)
- [Detection Engine Components](detection-engine/components.md)
- [Performance Tuning Guide](detection-engine/performance-tuning.md)
