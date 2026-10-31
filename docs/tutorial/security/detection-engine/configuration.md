# Detection Engine Configuration Guide

This guide provides comprehensive documentation for configuring the FastAPI Guard Detection Engine to optimize security and performance for your specific needs.

## Configuration Overview

The Detection Engine is configured through the `SecurityConfig` model, which provides numerous parameters to control detection behavior, performance characteristics, and integration options.

## Configuration Categories

### 1. Core Detection Settings

These settings control the fundamental behavior of the detection engine:

```python
from guard import SecurityConfig

config = SecurityConfig(
    # Enable/disable penetration detection
    enable_penetration_detection=True,  # Default: True
    # Auto-ban settings for suspicious activity
    auto_ban_threshold=10,  # Ban after N suspicious requests (default: 10)
    auto_ban_duration=3600,  # Ban duration in seconds (1 hour)
)
```

### 2. Detection Engine Settings

Fine-tune the detection engine components:

```python
config = SecurityConfig(
    # Pattern compilation and execution
    detection_compiler_timeout=2.0,  # Timeout for pattern matching (seconds)
    # Content preprocessing
    detection_max_content_length=10000,  # Max characters to analyze
    detection_preserve_attack_patterns=True,  # Preserve attacks during truncation
    # Semantic analysis
    detection_semantic_threshold=0.7,  # Threat score threshold (0.0-1.0)
)
```

### 3. Performance Monitoring Settings

Configure performance tracking and optimization:

```python
config = SecurityConfig(
    # Anomaly detection
    detection_anomaly_threshold=3.0,  # Standard deviations for anomaly
    # Pattern performance
    detection_slow_pattern_threshold=0.1,  # Slow pattern threshold (seconds)
    # Monitoring history
    detection_monitor_history_size=1000,  # Number of metrics to keep
    detection_max_tracked_patterns=1000,  # Maximum patterns to track
)
```

## Complete Configuration Example

Here's a comprehensive configuration example with all detection engine settings:

```python
from fastapi import FastAPI
from guard import SecurityMiddleware, SecurityConfig

app = FastAPI()

# Full detection engine configuration
config = SecurityConfig(
    # Core security settings
    enable_penetration_detection=True,
    auto_ban_threshold=5,
    auto_ban_duration=3600,
    passive_mode=False,  # Set to True for monitoring without blocking
    # Detection engine optimization
    detection_compiler_timeout=2.0,
    detection_max_content_length=10000,
    detection_preserve_attack_patterns=True,
    detection_semantic_threshold=0.7,
    # Performance monitoring
    detection_anomaly_threshold=3.0,
    detection_slow_pattern_threshold=0.1,
    detection_monitor_history_size=1000,
    detection_max_tracked_patterns=1000,
    # Redis integration (optional)
    enable_redis=True,
    redis_url="redis://localhost:6379/0",
    # Agent integration (optional)
    enable_agent=True,
    agent_api_key="your-api-key",
    agent_enable_events=True,
    agent_enable_metrics=True,
    # Logging
    custom_log_file="security.log",
    log_suspicious_level="WARNING",
)

app.add_middleware(SecurityMiddleware, config=config)
```

## Configuration Profiles

### High Security Profile

For applications requiring maximum security with stricter detection:

```python
high_security_config = SecurityConfig(
    # Strict detection settings
    enable_penetration_detection=True,
    auto_ban_threshold=3,  # Lower threshold
    auto_ban_duration=7200,  # Longer ban (2 hours)
    # Tighter detection parameters
    detection_compiler_timeout=1.0,  # Shorter timeout
    detection_max_content_length=5000,  # Analyze less content
    detection_semantic_threshold=0.5,  # More sensitive detection
    # Aggressive monitoring
    detection_anomaly_threshold=2.0,  # More sensitive to anomalies
    detection_slow_pattern_threshold=0.05,  # Stricter performance
)
```

### Performance Optimized Profile

For high-traffic applications prioritizing performance:

```python
performance_config = SecurityConfig(
    # Balanced detection
    enable_penetration_detection=True,
    auto_ban_threshold=10,  # Higher threshold
    auto_ban_duration=1800,  # Shorter ban (30 minutes)
    # Performance-focused settings
    detection_compiler_timeout=3.0,  # Longer timeout allowed
    detection_max_content_length=2000,  # Analyze less content
    detection_semantic_threshold=0.8,  # Less sensitive
    # Relaxed monitoring
    detection_anomaly_threshold=4.0,  # Less sensitive
    detection_slow_pattern_threshold=0.2,  # More tolerant
    detection_monitor_history_size=500,  # Smaller history
)
```

### Development Profile

For development and testing environments:

```python
dev_config = SecurityConfig(
    # Enable detection but in passive mode
    enable_penetration_detection=True,
    passive_mode=True,  # Log but don't block
    # Verbose settings for debugging
    detection_compiler_timeout=5.0,  # Generous timeout
    detection_max_content_length=50000,  # Large content analysis
    # Full monitoring
    detection_monitor_history_size=5000,  # Large history
    # Detailed logging
    log_suspicious_level="DEBUG",
    custom_log_file="security-debug.log",
)
```

## Parameter Reference

### Detection Compiler Settings

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `detection_compiler_timeout` | float | 2.0 | 0.1-10.0 | Maximum seconds for pattern execution |

**Usage Guidelines:**

- Lower values (0.1-1.0): High security, may timeout complex patterns
- Default (2.0): Balanced for most applications
- Higher values (3.0-5.0): More tolerant, for complex legitimate patterns

### Content Preprocessing Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `detection_max_content_length` | int | 10000 | Maximum characters to process |
| `detection_preserve_attack_patterns` | bool | True | Preserve attacks during truncation |

**Best Practices:**

- Set `max_content_length` based on your typical request size
- Always keep `preserve_attack_patterns` True for security
- Consider memory usage with very large content limits

### Semantic Analysis Settings

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `detection_semantic_threshold` | float | 0.7 | 0.0-1.0 | Score the semantic analyzer must exceed for a finding |

**Threshold Guidelines:**

- 0.0-0.3: Very sensitive, many false positives
- 0.4-0.6: Sensitive, catches more attacks
- 0.7-0.8: Balanced (recommended)
- 0.9-1.0: Very strict, may miss obfuscated attacks (1.0 produces no semantic finding) (1.0 produces no semantic finding)

### Performance Monitoring Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `detection_anomaly_threshold` | float | 3.0 | Standard deviations for anomaly |
| `detection_slow_pattern_threshold` | float | 0.1 | Seconds to consider pattern slow |
| `detection_monitor_history_size` | int | 1000 | Metrics to keep in memory |
| `detection_max_tracked_patterns` | int | 1000 | Maximum patterns to track |

**Optimization Tips:**

- Lower `anomaly_threshold` to catch unusual behavior earlier
- Adjust `slow_pattern_threshold` based on your performance requirements
- Increase history sizes for better long-term analysis

## Dynamic Configuration

You can adjust certain settings at runtime:

```python
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for

# The module-level objects are the default app's. Take the ones of the app
# you act on with the config that app was built with.
patterns = sus_patterns_manager_for(security_config)

# Adjust semantic threshold dynamically
await patterns.configure_semantic_threshold(0.8)

# Add custom patterns
await patterns.add_pattern(r"(?i)custom_threat_pattern", custom=True)

# Check component status
status = await patterns.get_component_status()
print(f"Components active: {status}")
```

## Configuration Validation

`SecurityConfig` validates every detection field against its range when it is created:

```python
try:
    config = SecurityConfig(
        detection_compiler_timeout=0.05  # Below the 0.1 minimum, rejected
    )
except ValueError as e:
    print(f"Configuration error: {e}")
```

## Environment Variables

`SecurityConfig` does not read environment variables. To configure the detection engine from the environment, read the values in your own code and pass them to the config:

```python
import os

config = SecurityConfig(
    enable_penetration_detection=os.environ.get("ENABLE_PENETRATION_DETECTION", "true")
    == "true",
    auto_ban_threshold=int(os.environ.get("AUTO_BAN_THRESHOLD", "10")),
    # Detection engine
    detection_compiler_timeout=float(
        os.environ.get("DETECTION_COMPILER_TIMEOUT", "2.0")
    ),
    detection_max_content_length=int(
        os.environ.get("DETECTION_MAX_CONTENT_LENGTH", "10000")
    ),
    detection_semantic_threshold=float(
        os.environ.get("DETECTION_SEMANTIC_THRESHOLD", "0.7")
    ),
    # Performance monitoring
    detection_anomaly_threshold=float(
        os.environ.get("DETECTION_ANOMALY_THRESHOLD", "3.0")
    ),
    detection_slow_pattern_threshold=float(
        os.environ.get("DETECTION_SLOW_PATTERN_THRESHOLD", "0.1")
    ),
)
```

## Monitoring Configuration Effectiveness

### Check Performance Impact

```python
# Get performance statistics
stats = await patterns.get_performance_stats()

# Analyze configuration effectiveness
if stats["summary"]["avg_execution_time"] > 0.05:
    print("Consider optimizing configuration for better performance")

if stats["summary"]["timeout_rate"] > 0.01:
    print("High timeout rate - consider increasing compiler_timeout")
```

### Monitor False Positives

```python
# Track false positive rate
if config.passive_mode:
    # In passive mode, analyze logs for false positives
    # Adjust detection_semantic_threshold based on findings
    pass
```

## Configuration Checklist

Before deploying to production:

- [ ] Test configuration in staging environment
- [ ] Verify timeout settings don't impact legitimate traffic
- [ ] Confirm content length limits handle your use cases
- [ ] Test semantic threshold with known attack patterns
- [ ] Monitor performance metrics for first 24 hours
- [ ] Review logs for false positives/negatives
- [ ] Ensure Redis/Agent connections are stable
- [ ] Document any custom patterns added

## Troubleshooting

### High False Positive Rate

```python
# Increase semantic threshold
config.detection_semantic_threshold = 0.8

# Review problematic patterns
stats = await patterns.get_performance_stats()
for pattern in stats["problematic_patterns"]:
    print(f"Review pattern: {pattern}")
```

### Performance Issues

```python
# Reduce content analysis size
config.detection_max_content_length = 5000

# Increase timeout tolerance
config.detection_compiler_timeout = 3.0

# Monitor specific patterns
slow_patterns = (await patterns.get_performance_stats())["slow_patterns"]
```

### Memory Usage

```python
# Reduce monitoring history
config.detection_monitor_history_size = 500
config.detection_max_tracked_patterns = 500

# The monitor keeps a bounded history (detection_monitor_history_size),
# so recorded metrics need no periodic cleanup
```

## Next Steps

- Review [Performance Tuning Guide](performance-tuning.md)
- Explore [Custom Pattern Development](../custom-patterns.md)
- Monitor with [Security Dashboard](../monitoring.md)
