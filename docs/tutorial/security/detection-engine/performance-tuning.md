# Detection Engine Performance Tuning Guide

This guide provides comprehensive strategies for optimizing the FastAPI Guard Detection Engine for maximum performance while maintaining security effectiveness.

## Performance Overview

The Detection Engine's performance is influenced by several factors:

- Pattern complexity and quantity
- Content size being analyzed
- Semantic analysis overhead
- Redis/Agent communication latency
- Concurrent request volume

## Performance Metrics

### Key Performance Indicators

Monitor these metrics to assess performance:

```python
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for

# The module-level objects are the default app's. Take the ones of the app
# you act on with the config that app was built with.
patterns = sus_patterns_manager_for(security_config)

# Get comprehensive performance statistics
# None until the app has handled its first request,
# which is when the detection engine is configured
stats = await patterns.get_performance_stats()

if stats is not None:
    # Key metrics to monitor
    print(f"Average execution time: {stats['summary']['avg_execution_time']}s")
    print(f"Timeout rate: {stats['summary']['timeout_rate'] * 100}%")
    print(f"Match rate: {stats['summary']['match_rate'] * 100}%")
    print(f"Slow patterns: {len(stats['slow_patterns'])}")
    print(f"Problematic patterns: {len(stats['problematic_patterns'])}")
```

### Performance Benchmarks

Target performance levels for different scenarios:

| Scenario | Target Response Time | Acceptable Timeout Rate |
|----------|---------------------|------------------------|
| API Gateway | < 10ms | < 0.1% |
| Web Application | < 50ms | < 1% |
| High Security | < 100ms | < 2% |
| Batch Processing | < 500ms | < 5% |

These are targets for your deployment, not engine guarantees. For scale, the engine's own detection on guard-core 5.0.0 (Python 3.11.18, arm64, async tree) takes 6.3 ms of CPU at the median and 10.8 ms at the 99th percentile for a 200-character benign value, 2.9 ms (p99 4.7 ms) for a value that carries an attack, and 19.7 ms (p99 28.1 ms) for a 10,000-character benign value. Across 1,000 pattern executions the performance monitor reported an average of 129 µs per pattern, a slowest of 16.0 ms and a timeout rate of 0%. Reproduce with `PYTHONPATH=. python -m perf_gate.detection_components latency --tree async` from a checkout of guard-core 5.0.0.

## Optimization Strategies

### 1. Pattern Optimization

#### Identify Slow Patterns

```python
# Get patterns exceeding threshold
# None until the app has handled its first request,
# which is when the detection engine is configured
slow_patterns = ((await patterns.get_performance_stats()) or {}).get(
    "slow_patterns", []
)

for pattern_info in slow_patterns:
    pattern = pattern_info["pattern"]
    avg_time = pattern_info["avg_execution_time"]

    if avg_time > 0.1:
        # Consider removing or optimizing
        print(f"Critical: {pattern} - {avg_time}s average")
```

#### Optimize Pattern Complexity

**Before (Slow):**

```python
# Catastrophic backtracking risk
pattern = r"(.*)*attack"
pattern = r"(a+)+b"
pattern = r"(\w+)*@(\w+)*\.com"
```

**After (Optimized):**

```python
# Atomic groups prevent backtracking
pattern = r"(?:.*?)attack"
pattern = r"(?:a+)b"
pattern = r"\w+@\w+\.com"
```

#### Use Non-Capturing Groups

```python
# Capture groups: no measurable cost here (CPU ratio 0.993 against itself at 200 characters, 0.999 at 10,000)
pattern = r"(SELECT|INSERT|UPDATE).*(FROM|INTO)"

# Non-capturing groups: the same speed (ratio 1.014 at 200 characters, 1.002 at 10,000); use them when you do not need the captured text
pattern = r"(?:SELECT|INSERT|UPDATE).*(?:FROM|INTO)"
```

### 2. Content Preprocessing Optimization

#### Adjust Content Length

```python
# For high-traffic APIs
config = SecurityConfig(
    detection_max_content_length=2000,  # Analyze less content (detection CPU on a 10,000-character benign value: ratio 0.767 against 1.007 for the default again)
    detection_preserve_attack_patterns=True,  # Still preserve threats
)

# For form submissions
config = SecurityConfig(
    detection_max_content_length=5000,  # Moderate analysis
)

# For file uploads
config = SecurityConfig(
    detection_max_content_length=1000,  # Minimal header analysis
)
```

#### Smart Truncation Strategy

```python
# Configure based on content type
if content_type == "application/json":
    config.detection_max_content_length = 5000
elif content_type == "multipart/form-data":
    config.detection_max_content_length = 1000
else:
    config.detection_max_content_length = 10000
```

### 3. Semantic Analysis Tuning

#### Disable for High-Performance Endpoints

```python
# Selectively disable semantic analysis
@app.get("/health")
async def health_check():
    # Skip semantic analysis for health checks
    return {"status": "ok"}


@app.post("/api/data")
async def process_data(request: Request):
    # Full analysis for data endpoints
    return await handle_request(request)
```

#### Adjust Semantic Threshold

```python
# Performance vs Security trade-off
# The threshold changes what is flagged, not the work done: detection costs the same CPU at 0.6, 0.7 and 0.8 (ratios to 0.7: benign value 1.013 and 1.015, against 1.007 for 0.7 again; value with an attack 1.000 and 1.002, against 1.003)
config = SecurityConfig(
    detection_semantic_threshold=0.8  # Only high-confidence threats
)

# For critical endpoints
config = SecurityConfig(
    detection_semantic_threshold=0.6  # More thorough analysis
)
```

### 4. Caching Optimization

#### Redis Configuration

```python
# Optimize Redis settings
config = SecurityConfig(
    enable_redis=True,
    redis_max_connections=20,  # Increase pool for high traffic
    redis_socket_timeout=2.0,  # Keep a slow Redis call from stalling requests
)
```

#### Pattern Compilation Cache

```python
# The compiled-pattern cache holds detection_max_tracked_patterns entries
# (at most 5000), so raise that setting to keep more patterns cached
config = SecurityConfig(detection_max_tracked_patterns=2000)
```

### 5. Timeout Configuration

#### Dynamic Timeout Adjustment

```python
# Base timeout on endpoint criticality
class DynamicTimeoutMiddleware:
    def __init__(self, app):
        self.app = app
        
    async def __call__(self, scope, receive, send):
        if scope["path"].startswith("/api/critical"):
            # Longer timeout for critical endpoints
            timeout = 3.0
        elif scope["path"].startswith("/static"):
            # Minimal timeout for static resources
            timeout = 0.5
        else:
            # Default timeout
            timeout = 2.0
            
        # Apply timeout
        scope["detection_timeout"] = timeout
        await self.app(scope, receive, send)
```

### 6. Parallel Processing

#### Batch Pattern Matching

```python
# Process multiple patterns in parallel
async def parallel_pattern_check(content: str, patterns: list):
    tasks = []
    for pattern in patterns:
        task = asyncio.create_task(check_pattern_async(content, pattern))
        tasks.append(task)

    results = await asyncio.gather(*tasks)
    return any(results)
```

## Performance Monitoring

### Real-time Monitoring

```python
import asyncio
from datetime import datetime


async def monitor_performance():
    while True:
        # None until the app has handled its first request,
        # which is when the detection engine is configured
        stats = await patterns.get_performance_stats()

        if stats is not None:
            # Alert on performance degradation
            if stats["summary"]["avg_execution_time"] > 0.05:
                logger.warning(
                    f"Performance degradation detected: "
                    f"{stats['summary']['avg_execution_time']}s average"
                )

            # Check for anomalies
            anomalies = stats["problematic_patterns"]
            if anomalies:
                logger.error(f"Pattern anomalies detected: {len(anomalies)}")

        await asyncio.sleep(60)  # Check every minute
```

### Performance Dashboard

```python
# Create performance metrics endpoint
@app.get("/metrics/detection-engine")
async def get_detection_metrics():
    # None until the app has handled its first request,
    # which is when the detection engine is configured
    stats = await patterns.get_performance_stats()

    if stats is None:
        return {}
    return {
        "performance": {
            "average_execution_ms": stats["summary"]["avg_execution_time"] * 1000,
            "max_execution_ms": stats["summary"]["max_execution_time"] * 1000,
            "timeout_rate": stats["summary"]["timeout_rate"],
            "total_executions": stats["summary"]["total_executions"],
        },
        "patterns": {
            "total": stats["summary"]["total_patterns"],
            "slow": len(stats["slow_patterns"]),
            "problematic": len(stats["problematic_patterns"]),
        },
        "health": calculate_health_score(stats),
    }
```

## Troubleshooting Performance Issues

### High CPU Usage

```python
# 1. Check for runaway patterns
# None until the app has handled its first request,
# which is when the detection engine is configured
problematic = ((await patterns.get_performance_stats()) or {}).get(
    "problematic_patterns", []
)
for pattern in problematic:
    if pattern["timeout_rate"] > 0.05:
        # Remove or fix pattern
        await patterns.remove_pattern(pattern["pattern"], custom=True)

# 2. Bound the work done per request
config.detection_max_scan_values = 256  # Scan fewer values per request


# 3. Implement circuit breaker
class CircuitBreaker:
    def __init__(self, threshold=0.5, timeout=60):
        self.threshold = threshold
        self.timeout = timeout
        self.failures = 0
        self.last_failure = None
```

### Memory Issues

```python
# 1. Reduce history size
config = SecurityConfig(
    detection_monitor_history_size=500,  # Smaller history
    detection_max_tracked_patterns=500,  # Track fewer patterns
)


# 2. Clear old data periodically
async def cleanup_task():
    while True:
        await patterns._performance_monitor.clear_stats()
        await patterns._compiler.clear_cache()
        await asyncio.sleep(3600)  # Every hour


# 3. Monitor memory usage
import psutil

process = psutil.Process()
memory_mb = process.memory_info().rss / 1024 / 1024
```

### Latency Spikes

```python
# 1. Implement request sampling
class SamplingMiddleware:
    def __init__(self, sample_rate=0.1):
        self.sample_rate = sample_rate

    async def should_analyze(self, request):
        # Only analyze sample of requests
        return random.random() < self.sample_rate


# 2. Priority queue for critical paths
critical_paths = {"/api/payment", "/api/auth"}
if request.path in critical_paths:
    # Full analysis
    result = await detect_full(content)
else:
    # Light analysis
    result = await detect_light(content)
```

## Best Practices

### 1. Regular Pattern Audits

```python
# Weekly pattern review
async def audit_patterns():
    # None until the app has handled its first request,
    # which is when the detection engine is configured
    stats = await patterns.get_performance_stats()

    if stats is not None:
        # Remove ineffective patterns
        for pattern in stats["all_patterns"]:
            if pattern["match_rate"] < 0.0001 and pattern["age_days"] > 30:
                logger.info(f"Removing ineffective pattern: {pattern['pattern']}")
                await patterns.remove_pattern(pattern["pattern"])

        # Optimize slow patterns
        for pattern in stats["slow_patterns"]:
            optimized = optimize_pattern(pattern["pattern"])
            if optimized != pattern["pattern"]:
                await patterns.remove_pattern(pattern["pattern"])
                await patterns.add_pattern(optimized, custom=True)
```

### 2. Load Testing

```python
# Performance test script
import asyncio
import time


async def load_test():
    test_contents = [
        "normal request data",
        "SELECT * FROM users WHERE id=1",
        "<script>alert('xss')</script>",
        # Add more test cases
    ]

    start = time.time()
    tasks = []

    for _ in range(1000):
        for content in test_contents:
            task = patterns.detect(
                content=content, ip_address="127.0.0.1", context="load_test"
            )
            tasks.append(task)

    results = await asyncio.gather(*tasks)
    elapsed = time.time() - start

    print(f"Processed {len(tasks)} requests in {elapsed:.2f}s")
    print(f"Average: {elapsed / len(tasks) * 1000:.2f}ms per request")
```

### 3. Gradual Rollout

```python
# Feature flag for new patterns
NEW_PATTERNS_ENABLED = False

if NEW_PATTERNS_ENABLED:
    await patterns.add_pattern(new_pattern, custom=True)

# Canary deployment
if hash(request.client.host) % 100 < 10:  # 10% of users
    # Use new detection settings
    config.detection_semantic_threshold = 0.6
else:
    # Use stable settings
    config.detection_semantic_threshold = 0.7
```

## Performance Checklist

Before deploying to production:

- [ ] Average execution time < 50ms
- [ ] Timeout rate < 1%
- [ ] No patterns with > 100ms average execution
- [ ] Pattern validation cache hit rate above 80% after a restart (`detection_pattern_validation_cache_path` set)
- [ ] Memory usage stable over 24 hours
- [ ] CPU usage < 20% under normal load
- [ ] Tested with 10x expected traffic
- [ ] Monitoring alerts configured
- [ ] Rollback plan prepared

For scale, measured on guard-core 5.0.0 (async tree): detecting a 200-character benign value takes 6.3 ms of CPU, so 20% of one core covers about 32 such detections per second; the monitor's average per-pattern execution time was 129 µs with a timeout rate of 0% (`PYTHONPATH=. python -m perf_gate.detection_components latency --tree async`). The cache hit rate comes from `await sus_patterns_handler.get_cache_stats()` (`["pattern_validation"]["hit_rate"]`): with 20 custom patterns it was 0.0 at the first boot and 1.0 at the second boot on the same cache file (`PYTHONPATH=. python -m perf_gate.cache_hit_rate`). The compiled-pattern cache (`["compiled_patterns"]`) is the one the blocked user-agent patterns and `add_pattern` compile through, so its hit rate rises with traffic when `blocked_user_agents` is set; adding or removing a pattern clears it and the counters survive the clear.

## Next Steps

- Implement [Custom Patterns](../custom-patterns.md) optimized for performance
- Configure [Monitoring Dashboard](../monitoring.md) for real-time insights
- Review [Architecture Guide](architecture.md) for optimization opportunities
