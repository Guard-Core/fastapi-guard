# Detection Engine Components

This document provides detailed information about each component of the FastAPI Guard Detection Engine, including their actual implementation, capabilities, and usage.

## Component Overview

The Detection Engine consists of four main components, all built together when the pattern manager is configured:

1. **ContentPreprocessor** - Normalizes, decodes and truncates content while preserving attack patterns
2. **PatternCompiler** - Provides timeout-protected pattern matching
3. **SemanticAnalyzer** - Heuristic-based attack detection
4. **PerformanceMonitor** - Tracks execution metrics

## ContentPreprocessor

Located in `guard_core.detection_engine.preprocessor` (the `FastAPI Guard` adapter ships no copy of it).

### Purpose

Normalizes content, decodes common encodings and truncates it to prevent excessive memory usage while ensuring potential attack patterns are preserved.

### Implementation

```python
class ContentPreprocessor:
    """Intelligent content preprocessing with attack pattern preservation."""

    def __init__(
        self,
        max_content_length: int = 10000,
        preserve_attack_patterns: bool = True,
        agent_handler: AgentHandlerProtocol | None = None,
        correlation_id: str | None = None,
        max_full_scan_bytes: int | None = None,
    ): ...
```

The pattern manager builds it from `detection_max_content_length` and `detection_preserve_attack_patterns`.

### Key Methods

#### `async preprocess(content: str, decode_budget_exhausted: list[bool] | None = None) -> str`

Preprocesses content with the following steps:

1. Empty content returns `""`
2. `normalize_unicode()` normalizes the Unicode form
3. `decode_common_encodings()` decodes URL, HTML-entity, hex, base64 and similar encodings
4. `remove_null_bytes()` drops null bytes and control characters (tab, newline and carriage return stay)
5. `remove_excessive_whitespace()` collapses runs of whitespace
6. `truncate_safely()` shortens content longer than `max_content_length`; with `preserve_attack_patterns` on, the regions that `extract_attack_regions()` finds are kept

`preprocess_with_decoded()` returns the processed content together with the decoded content before truncation, and `preprocess_batch()` processes a list (all three are coroutines).

### Attack Pattern Preservation

The preprocessor looks for indicators like:

- SQL keywords: SELECT, UNION, INSERT, DELETE, etc.
- Script tags and JavaScript events
- Path traversal patterns: ../, ..\
- Command injection indicators
- Common encoding patterns

### Example Usage

```python
from guard_core.detection_engine.preprocessor import ContentPreprocessor

preprocessor = ContentPreprocessor(
    max_content_length=config.detection_max_content_length,
    preserve_attack_patterns=config.detection_preserve_attack_patterns,
)
processed = await preprocessor.preprocess(long_content)
# Result: Truncated content with attack patterns preserved
```

## PatternCompiler

Located in `guard_core.detection_engine.compiler`.

### Purpose

Provides safe pattern compilation and execution with timeout protection against ReDoS attacks.

### Implementation

```python
class PatternCompiler:
    """Pattern compilation with timeout protection."""

    def __init__(
        self,
        default_timeout: float = 5.0,
        max_cache_size: int = 1000,
        validation_cache: PatternValidationCache | None = None,
        redaction_names: _SensitiveNameSets | None = None,
    ): ...
```

The pattern manager passes `detection_compiler_timeout` as `default_timeout` and `detection_max_tracked_patterns` as `max_cache_size`. The cache never grows beyond 5000 entries.

### Key Methods

#### `async compile_pattern(pattern: str, flags: int = re.IGNORECASE | re.MULTILINE) -> re.Pattern`

Compiles regex patterns:

- Caches compiled patterns for performance (least recently used patterns are evicted)
- Raises for an invalid pattern
- `batch_compile()` compiles a list (also a coroutine) and `validate_pattern_safety()` tests a pattern against ReDoS inputs

#### `create_safe_matcher(pattern: str | re.Pattern, timeout: float | None = None, inline_safe: bool = False) -> Callable[[str], re.Match | None]`

Creates a timeout-protected matcher function:

```python
matcher = compiler.create_safe_matcher(r"(?i)select\s+\*", timeout=2.0)
match = matcher("SELECT * FROM users")  # re.Match, or None when nothing matches
```

`create_safe_finditer_matcher()` returns every match instead of the first one.

### Timeout Protection

- Uses thread-based execution with a configurable timeout (`detection_compiler_timeout`)
- Runs pattern matching in a thread pool to prevent blocking
- A scan that exceeds its time budget is cut off instead of hanging

## SemanticAnalyzer

Located in `guard_core.detection_engine.semantic`.

### Purpose

Provides heuristic-based detection of obfuscated attacks that might bypass regex patterns.

### Implementation

```python
class SemanticAnalyzer:
    """Heuristic-based semantic analysis for attack detection."""

    def __init__(self) -> None: ...
```

The analyzer takes no configuration. The threshold (`detection_semantic_threshold`) is applied by the pattern manager to the analyzer's score.

### Key Methods

#### `analyze(content: str) -> SemanticAnalysis`

Performs the analysis:

1. **Token Extraction**: `extract_tokens()` breaks content into tokens
2. **Attack Probabilities**: `analyze_attack_probability()` scores each attack family from the tokens
3. **Obfuscation**: entropy, encoding layers and obfuscation checks
4. **Suspicious Patterns**: `extract_suspicious_patterns()` finds attack-like structures

`get_threat_score(analysis)` combines the analysis into one score from 0.0 to 1.0.

### Attack Detection Heuristics

The analyzer scores these keyword families (`xss`, `sql`, `command`, `path`, `template`):

- **SQL (`sql`)**: select, union, insert, update, delete, drop, from, where, concat, substring and similar
- **XSS (`xss`)**: script, javascript, onerror, onload, onclick, alert, eval, document, cookie and similar
- **Path (`path`)**: etc, passwd, shadow, hosts, proc, boot, win, ini
- **Command (`command`)**: exec, system, shell, cmd, bash, wget, curl, nc, chmod, sudo and similar
- **Template (`template`)**: render, template, jinja, mustache, handlebars, ejs, pug, twig

It also looks at suspicious characters (brackets, quotes, slashes, shell operators, wildcards) and attack structures (tag-like text, function calls, command chains, path traversal, URL schemes).

### Scoring System

```python
{
    "attack_probabilities": {
        "sql": 0.9,
        "xss": 0.3,
        "command": 0.0,
        "path": 0.0,
        "template": 0.0,
    },
    "entropy": 4.1,
    "encoding_layers": 0,
    "is_obfuscated": False,
    "suspicious_patterns": [...],
    "code_injection_risk": 0.0,
    "token_count": 12,
}
```

`get_threat_score()` turns that analysis into a score from 0.0 to 1.0.

## PerformanceMonitor

Located in `guard_core.detection_engine.monitor`.

### Purpose

Tracks pattern execution performance to identify bottlenecks and optimize detection.

### Implementation

```python
class PerformanceMonitor:
    """Real-time performance monitoring for detection operations."""

    def __init__(
        self,
        anomaly_threshold: float = 3.0,
        slow_pattern_threshold: float = 0.1,
        history_size: int = 1000,
        max_tracked_patterns: int = 1000,
        anomaly_emission_cooldown: float = 60.0,
        min_samples_for_anomaly: int = 30,
        redaction_names: _SensitiveNameSets | None = None,
    ): ...
```

The pattern manager builds it from `detection_anomaly_threshold`, `detection_slow_pattern_threshold`, `detection_monitor_history_size`, `detection_max_tracked_patterns`, `detection_anomaly_emission_cooldown` and `detection_min_samples_for_anomaly`.

### Key Methods

#### `async record_metric(pattern, execution_time, content_length, matched, timeout=False, ...)`

Records execution metrics:

- Pattern identifier
- Execution time
- Content length
- Match result
- Timeout status

#### `get_pattern_report(pattern: str) -> PatternReport | None`

Returns statistics for a specific pattern:

```python
{
    "pattern": "complex.*regex.*pattern",
    "pattern_hash": "83913001",
    "total_executions": 150,
    "total_matches": 5,
    "total_timeouts": 2,
    "match_rate": 0.033,
    "timeout_rate": 0.013,
    "avg_execution_time": 0.003,
    "max_execution_time": 0.125,
    "min_execution_time": 0.001,
}
```

#### `async get_slow_patterns(limit: int = 10) -> list[PatternReport]`

Returns the `limit` patterns with the highest average execution time, in the same shape as `get_pattern_report()`:

```python
[
    {
        "pattern": "complex.*regex.*pattern",
        "avg_execution_time": 0.150,
        "total_executions": 100,
        "timeout_rate": 0.05,
        # ... the other get_pattern_report() fields
    }
]
```

#### `async get_problematic_patterns() -> list[PatternReport]`

Returns the patterns whose timeout rate is above 10% (`issue` is `high_timeout_rate`) or whose average execution time is above `slow_pattern_threshold` (`issue` is `consistently_slow`), in the same shape as `get_pattern_report()` plus the `issue` key.

#### `async get_summary_stats() -> PerformanceSummary`

Returns `total_executions`, `avg_execution_time`, `max_execution_time`, `min_execution_time`, `timeout_rate`, `match_rate` and `total_patterns`.

#### Anomaly detection

Anomalies (timeouts, slow executions and statistical outliers beyond `anomaly_threshold` standard deviations) are checked as metrics are recorded. `register_anomaly_callback(callback)` registers a callback that receives each anomaly as a dict.

### Memory Management

- Fixed-size history (`history_size`) prevents unbounded growth
- Automatic cleanup of old metrics
- Per-pattern tracking limited by `max_tracked_patterns`

## Component Initialization

Components are built together when the pattern manager is configured, in `_build_enhanced_detection_state()` (`guard_core.handlers._suspatterns_state`):

```python
def _build_enhanced_detection_state(config, redaction_names=None):
    return _DetectionState(
        compiler=PatternCompiler(
            default_timeout=config.detection_compiler_timeout,
            max_cache_size=config.detection_max_tracked_patterns,
            # ...
        ),
        preprocessor=ContentPreprocessor(
            max_content_length=config.detection_max_content_length,
            preserve_attack_patterns=config.detection_preserve_attack_patterns,
            # ...
        ),
        semantic_analyzer=SemanticAnalyzer(),
        performance_monitor=PerformanceMonitor(
            anomaly_threshold=config.detection_anomaly_threshold,
            slow_pattern_threshold=config.detection_slow_pattern_threshold,
            history_size=config.detection_monitor_history_size,
            max_tracked_patterns=config.detection_max_tracked_patterns,
            # ...
        ),
        semantic_threshold=config.detection_semantic_threshold,
        threat_score_threshold=config.detection_threat_score_threshold,
    )
```

## Component Interaction

The components work together in the `detect()` method:

1. **Preprocessing**: Content is normalized, decoded and truncated
2. **Pattern Matching**: Each pattern is executed with timeout protection
3. **Semantic Analysis**: Additional heuristic checks, skipped for binary content
4. **Performance Tracking**: All operations are monitored

### Example Flow

```python
async def detect(
    self,
    content: str,
    ip_address: str,
    context: str = "unknown",
    correlation_id: str | None = None,
    **options,
) -> dict:
    # 1. Preprocess (normalize, decode, truncate)
    processed, decode_budget_exhausted, decoded = await self._preprocess_content(
        content, correlation_id
    )

    # 2. Pattern matching with the compiler, each pattern under its timeout
    #    -> regex threats: {"type": "regex", "pattern": ..., "match": ..., "category": ...}

    # 3. Semantic analysis
    semantic_threats, semantic_score = await self._check_semantic_threats(processed)
    #    -> {"type": "semantic", "attack_type": ..., "probability": ..., "analysis": ...}
    #    (added when the score is above detection_semantic_threshold)

    # 4. Record performance for every pattern that ran
    #    performance_monitor.record_metric(pattern, execution_time, content_length, matched, timeout)

    return {
        "is_threat": bool(threats),
        "threat_score": threat_score,  # 0.0-1.0
        "threats": threats,
        # ... context, lengths, execution_time, detection_method, timeouts, correlation_id
    }
```

## Error Handling

Each component includes error handling:

- **PatternCompiler**: Invalid patterns raise, and the matchers cut off a scan that exceeds its time budget
- **ContentPreprocessor**: Handles encoding errors gracefully
- **SemanticAnalyzer**: Caps the content it reads
- **PerformanceMonitor**: Bounded history, no unbounded growth

## Performance Optimization

### Caching

- Compiled patterns are cached in PatternCompiler
- Validation results can persist in the cache file named by `detection_pattern_validation_cache_path`

### Synchronous Operations

- Pattern matching runs in a thread pool for timeout protection, awaited from the event loop

### Memory Bounds

- All collections have size limits
- Old data is automatically evicted

## Configuration Impact

| Component | Configuration | Effect |
|-----------|---------------|--------|
| ContentPreprocessor | `detection_max_content_length`, `detection_preserve_attack_patterns` | Truncation length and attack-region preservation |
| PatternCompiler | `detection_compiler_timeout`, `detection_max_tracked_patterns` | Timeout per pattern and cache size |
| SemanticAnalyzer | `detection_semantic_threshold` | Score above which a semantic threat is reported |
| PerformanceMonitor | `detection_anomaly_threshold`, `detection_slow_pattern_threshold`, `detection_monitor_history_size`, `detection_max_tracked_patterns` | Anomaly, slow-pattern and history limits |

All four components are always created.

## Best Practices

1. **Keep Timeout Protection Tight**: Keep `detection_compiler_timeout` low to bound the cost of a pathological pattern
2. **Set Content Limits**: Use `detection_max_content_length` to bound memory usage
3. **Monitor Performance**: Review slow patterns regularly
4. **Test Semantic Threshold**: Adjust based on false positive tolerance
5. **Clean Up Patterns**: Remove or optimize slow patterns

## Next Steps

- Learn about [Configuration Options](configuration.md)
- Review [Performance Tuning](performance-tuning.md)
- See [Architecture Overview](architecture.md)
