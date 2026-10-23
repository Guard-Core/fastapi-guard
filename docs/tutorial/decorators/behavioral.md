---

title: Behavioral Analysis Decorators - FastAPI Guard
description: Learn how to use behavioral analysis decorators for usage monitoring, return pattern detection, and anomaly analysis
keywords: behavioral analysis, usage monitoring, pattern detection, anomaly detection, security decorators
---

Behavioral Analysis Decorators
==============================

Behavioral analysis decorators provide advanced monitoring capabilities to detect suspicious usage patterns, automated behavior, and potential abuse of your API endpoints. These decorators help identify bots, scrapers, and malicious users through behavioral analysis.

___

Enabling behavioral decorators
------------------------------

Behavioral decorators are wired into the running middleware in three steps. The third step is what actually makes the rules fire - attaching a decorator without it leaves the rule inert.

```python
from fastapi import FastAPI

from guard import SecurityConfig, SecurityDecorator, SecurityMiddleware

app = FastAPI()

# 1. Configure and install the middleware
config = SecurityConfig(enable_penetration_detection=True)
app.add_middleware(SecurityMiddleware, config=config)

# 2. Build a decorator bound to the same config
guard_deco = SecurityDecorator(config)

# 3. Wire the decorator into the middleware - REQUIRED
app.state.guard_decorator = guard_deco


@app.get("/api/sensitive")
@guard_deco.usage_monitor(max_calls=10, window=3600, action="ban")
async def sensitive_endpoint() -> dict[str, str]:
    return {"data": "sensitive information"}
```

**Without `app.state.guard_decorator = guard_deco`, the decorators attach to your routes but their rules never fire** - the middleware has no handle on the decorator, so no behavioral evaluation runs. If you hold the `SecurityMiddleware` instance directly rather than using `add_middleware`, the equivalent call is `middleware.set_decorator_handler(guard_deco)`.

Every decorator example below assumes this wiring is in place.

___

Usage Monitoring
----------------

Monitor how frequently individual IPs access specific endpoints:

. Basic Usage Monitoring
----------------------

```python
from guard import SecurityDecorator

guard_deco = SecurityDecorator(config)


@app.get("/api/sensitive")
@guard_deco.usage_monitor(max_calls=10, window=3600, action="ban")
def sensitive_endpoint():
    return {"data": "sensitive information"}
```

. Gaming Endpoint Protection
--------------------------

```python
@app.post("/api/game/lootbox")
@guard_deco.usage_monitor(max_calls=5, window=3600, action="ban")
def lootbox_endpoint():
    # Prevent lootbox farming
    return {"reward": "rare_item", "value": 1000}


@app.post("/api/game/daily-reward")
@guard_deco.usage_monitor(max_calls=1, window=86400, action="ban")
def daily_reward():
    # Only once per day per IP
    return {"reward": "daily_bonus", "amount": 100}
```

. API Rate Abuse Detection
------------------------

```python
@app.get("/api/expensive-computation")
@guard_deco.usage_monitor(max_calls=3, window=3600, action="throttle")
def expensive_operation():
    # Prevent abuse of computationally expensive operations
    return {"result": "computed_data"}


@app.get("/api/search")
@guard_deco.usage_monitor(max_calls=100, window=3600, action="alert")
def search_endpoint():
    # Monitor for search abuse but don't block immediately
    return {"results": "search_data"}
```

___

Return Pattern Monitoring
-------------------------

Detect when the same IP receives specific responses too frequently:

**Body-content `return_pattern` rules changed behavior in 3.12.0.** Before fastapi-guard 7.6.0, patterns like `"win"`, `json:...`, and `regex:...` never matched in production, since the response body was unreadable through the middleware and the failure was silent. As of guard-core 3.12.0 with fastapi-guard >= 7.6.0 they work, but stay opt-in: every example below needs `SecurityConfig(behavior_scan_response_body=True)`, or guard-core raises `ValueError` at construction naming the pattern. Streaming responses are scanned only on their first streamed chunk (up to `behavior_max_response_body_inspect_bytes`); non-streaming responses are scanned whole, up to the same cap.

. Win/Success Pattern Detection
----------------------------

```python
@app.post("/api/lottery")
@guard_deco.return_monitor("win", max_occurrences=2, window=86400, action="ban")
def lottery_endpoint():
    # Prevent lottery manipulation
    result = random.choice(["win", "lose", "lose", "lose"])
    return {"result": result, "prize": 1000 if result == "win" else 0}
```

. Reward System Protection
------------------------

```python
@app.get("/api/rewards/spin")
@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400, action="ban")
def spin_wheel():
    # Prevent rare item farming
    items = ["common", "common", "rare_item", "common"]
    result = random.choice(items)
    return {"item": result, "rarity": "rare" if result == "rare_item" else "common"}
```

. JSON Path Pattern Matching
--------------------------

```python
@app.post("/api/game/battle")
@guard_deco.return_monitor(
    "json:result.outcome==victory", max_occurrences=10, window=3600, action="alert"
)
def battle_endpoint():
    # Monitor for suspicious win rates
    return {
        "result": {"outcome": "victory", "experience": 100, "loot": ["sword", "gold"]}
    }
```

. Regex Pattern Detection
----------------------

```python
@app.get("/api/contest/submit")
@guard_deco.return_monitor(
    "regex:(success|winner|prize)", max_occurrences=5, window=86400, action="ban"
)
def contest_submission():
    # Detect multiple contest wins from same IP
    return {"status": "success", "message": "Contest entry submitted"}
```

___

Frequency Detection
-------------------

Detect suspiciously high request frequencies:

. Slow Operations Protection
--------------------------

```python
@app.post("/api/report/generate")
@guard_deco.suspicious_frequency(max_frequency=0.1, window=300, action="ban")
def generate_report():
    # Max 1 request per 10 seconds (0.1 requests/second)
    return {"status": "Report generation started"}


@app.post("/api/backup/create")
@guard_deco.suspicious_frequency(max_frequency=0.017, window=3600, action="ban")
def create_backup():
    # Max 1 request per minute (0.017 requests/second)
    return {"status": "Backup initiated"}
```

. API Scraping Prevention
----------------------

```python
@app.get("/api/products/{product_id}")
@guard_deco.suspicious_frequency(max_frequency=2.0, window=300, action="alert")
def product_details(product_id: int):
    # Alert if more than 2 requests per second for 5 minutes
    return {"product": f"Product {product_id}", "price": 99.99}
```

___

Complex Behavioral Analysis
---------------------------

Combine multiple behavioral rules for comprehensive protection. The `return_pattern` rules below match response body content (`"win"`, `"critical_hit"`, `"profit"`), so pair `guard_deco`'s `SecurityConfig` with `behavior_scan_response_body=True`; body-content patterns also require fastapi-guard >= 7.6.0's bounded response-body reader, or guard-core raises `ValueError` at construction naming the pattern.

. Multi-Rule Analysis
-------------------

```python
from guard import BehaviorRule

# Define multiple rules
rules = [
    BehaviorRule("usage", threshold=20, window=3600, action="alert"),
    BehaviorRule(
        "return_pattern", threshold=5, pattern="win", window=86400, action="ban"
    ),
    BehaviorRule("frequency", threshold=60, window=300, action="throttle"),
]


@app.post("/api/casino/play")
@guard_deco.behavior_analysis(rules)
def casino_game():
    # Protected by multiple behavioral rules
    return {"result": "win", "amount": 500}
```

. Gaming Platform Protection
--------------------------

```python
# Comprehensive gaming endpoint protection
@app.post("/api/game/action")
@guard_deco.usage_monitor(max_calls=100, window=3600, action="alert")
@guard_deco.return_monitor(
    "critical_hit", max_occurrences=10, window=3600, action="ban"
)
@guard_deco.suspicious_frequency(max_frequency=5.0, window=60, action="throttle")
def game_action():
    # Multi-layered protection against game exploitation
    return {"action": "attack", "result": "critical_hit", "damage": 150}
```

. Financial API Protection
------------------------

```python
@app.post("/api/trading/execute")
@guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")
@guard_deco.return_monitor("profit", max_occurrences=20, window=86400, action="alert")
@guard_deco.suspicious_frequency(max_frequency=1.0, window=60, action="ban")
def execute_trade():
    # Prevent trading bot abuse
    return {"status": "executed", "result": "profit", "amount": 1000}
```

___

Action Types
------------

Different actions can be taken when behavioral thresholds are exceeded:

. Ban Action
----------

```python
@guard_deco.usage_monitor(max_calls=5, window=3600, action="ban")
def strict_endpoint():
    # Immediately ban IPs that exceed threshold
    return {"data": "strictly protected"}
```

. Alert Action
------------

The pattern below matches response body content (`"suspicious_pattern"`), so pair it with `SecurityConfig(behavior_scan_response_body=True)`; body-content patterns also require fastapi-guard >= 7.6.0's bounded response-body reader, or guard-core raises `ValueError` at construction naming the pattern.

```python
@guard_deco.return_monitor(
    "suspicious_pattern", max_occurrences=3, window=3600, action="alert"
)
def monitored_endpoint():
    # Log alerts but don't block access
    return {"status": "monitored"}
```

. Throttle Action
---------------

`action="throttle"` only logs the violation; it does not delay, rate-limit, or block the request.

```python
@guard_deco.suspicious_frequency(max_frequency=2.0, window=300, action="throttle")
def logged_frequency_endpoint():
    # Logs a warning when threshold exceeded, request still proceeds
    return {"data": "monitored access"}
```

. Log Action
----------

```python
@guard_deco.usage_monitor(max_calls=100, window=3600, action="log")
def logged_endpoint():
    # Only log incidents for analysis
    return {"data": "logged access"}
```

___

Advanced Pattern Formats
------------------------

. Status Code Monitoring
----------------------

```python
@guard_deco.return_monitor(
    "status:200", max_occurrences=1000, window=3600, action="alert"
)
def success_monitored():
    # Monitor successful request patterns
    return {"status": "success"}
```

. Complex JSON Patterns
---------------------

Both examples below inspect the response body, so they require `behavior_scan_response_body=True` on the `SecurityConfig` and fastapi-guard >= 7.6.0; without the flag, guard-core raises `ValueError` at construction naming the pattern.

```python
@guard_deco.return_monitor(
    "json:user.level>50", max_occurrences=5, window=86400, action="ban"
)
def level_up():
    # Detect suspicious leveling patterns
    return {"user": {"level": 55, "experience": 10000}}


@guard_deco.return_monitor(
    "json:transaction.amount>10000", max_occurrences=3, window=86400, action="alert"
)
def high_value_transaction():
    # Monitor large transactions
    return {"transaction": {"amount": 15000, "currency": "USD"}}
```

___

Best Practices
--------------

. Set Realistic Thresholds
---------------------------

Base thresholds on legitimate user behavior:

```python
# Good: Based on actual usage patterns
@guard_deco.usage_monitor(max_calls=50, window=3600, action="alert")  # 50/hour is reasonable

# Avoid: Too restrictive for normal users
# @guard_deco.usage_monitor(max_calls=3, window=3600, action="ban")  # Too strict
```

. Use Graduated Responses
-----------------------

Start with monitoring, then escalate to blocking:

```python
# Progressive enforcement
@guard_deco.usage_monitor(max_calls=20, window=3600, action="log")      # Log at 20
@guard_deco.usage_monitor(max_calls=50, window=3600, action="alert")    # Alert at 50
@guard_deco.usage_monitor(max_calls=100, window=3600, action="ban")     # Ban at 100
```

. Monitor Valuable Operations
---------------------------

Focus on endpoints that provide value to attackers. The `return_monitor` example below matches response body content (`"rare_reward"`), so pair it with `SecurityConfig(behavior_scan_response_body=True)`; body-content patterns also require fastapi-guard >= 7.6.0's bounded response-body reader, or guard-core raises `ValueError` at construction naming the pattern.

```python
# High-value endpoints
@guard_deco.return_monitor("rare_reward", max_occurrences=2, window=86400, action="ban")

# Financial operations
@guard_deco.usage_monitor(max_calls=10, window=3600, action="ban")

# Data extraction points
@guard_deco.suspicious_frequency(max_frequency=1.0, window=60, action="throttle")
```

. Consider Time Windows Carefully
-------------------------------

Match windows to expected usage patterns:

```python
# Daily limits for once-per-day operations
@guard_deco.usage_monitor(max_calls=1, window=86400, action="ban")

# Hourly limits for regular operations
@guard_deco.usage_monitor(max_calls=50, window=3600, action="alert")

# Short-term frequency detection
@guard_deco.suspicious_frequency(max_frequency=2.0, window=300, action="throttle")
```

___

Integration with Redis
---------------------

For distributed applications, ensure Redis is configured:

```python
config = SecurityConfig(
    enable_redis=True, redis_url="redis://localhost:6379", redis_prefix="fastapi_guard:"
)

# Behavioral tracking will use Redis for distributed state
guard_deco = SecurityDecorator(config)
```

___

Error Handling
--------------

Behavioral decorators integrate with middleware error handling:

- **403 Forbidden**: When action is "ban"
- **Logging only, no blocking**: When action is "log", "throttle", or "alert" (the request still proceeds)

. Custom Error Messages
---------------------

```python
config = SecurityConfig(
    custom_error_responses={
        403: "Behavioral analysis detected suspicious activity",
    }
)
```

___

Monitoring and Debugging
------------------------

Enable detailed logging to monitor behavioral analysis:

```python
config = SecurityConfig(log_suspicious_level="DEBUG", log_request_level="INFO")

# Logs will include:
# - Behavioral rule violations
# - Pattern matching results
# - Action execution details
```

___

Testing Behavioral Rules
-----------------------

Test your behavioral decorators:

```python
import pytest
from fastapi.testclient import TestClient


def test_usage_monitor():
    # Should allow normal usage
    for i in range(5):
        response = client.get("/api/monitored")
        assert response.status_code == 200

    # Should block after threshold
    response = client.get("/api/monitored")
    assert response.status_code == 403


def test_return_pattern():
    # Mock responses to trigger pattern
    with patch("random.choice", return_value="win"):
        for i in range(3):
            response = client.post("/api/lottery")
            if i < 2:
                assert response.status_code == 200
            else:
                assert response.status_code == 403  # Blocked after 2 wins
```

___

Verifying it works
------------------

Once the decorator is wired (see [Enabling behavioral decorators](#enabling-behavioral-decorators)), confirm rules are firing end to end:

- **Trip a low-threshold rule.** Set a deliberately small threshold - e.g. `@guard_deco.usage_monitor(max_calls=2, window=60, action="log")` - and call the route a few times. On the threshold breach the engine's `BehavioralProcessor` emits a `decorator_violation` event.
- **Observe the outcome.** What you see depends on the rule's `action`: `log` and `throttle` write a log line and let the request proceed, and `ban` returns `403`. With the Guard Agent enabled, the `decorator_violation` events are also shipped to your dashboard, so you can confirm a rule fired even when its action is `log` or `throttle`.
- **Trial safely with passive mode.** Set `passive_mode=True` on the `SecurityConfig` to run behavioral rules in log-only mode: violations are recorded with the `[PASSIVE MODE]` prefix instead of blocking, so you can validate thresholds against production traffic before enforcing. See [Security Monitoring](../security/monitoring.md).

If a route's rule never fires, the wiring step is almost always the cause - verify `app.state.guard_decorator` is set to the same decorator that decorates the route.

___

Per-route rules vs. fleet-wide rules
------------------------------------

The decorators on this page attach rules to a **single route**. To apply a rule to **every route** - for example fleet-wide 404 / scraping tracking - set `SecurityConfig.global_behavior_rules` instead. Global rules need no per-route decorator and no `app.state.guard_decorator` wiring; they are evaluated by the middleware for all traffic.

The two compose: a decorated route is evaluated against both its own decorator rules and any `global_behavior_rules`. Reach for decorators when a limit is specific to an endpoint, and `global_behavior_rules` when a policy should hold everywhere. See the [Security Config reference](../configuration/security-config.md) for the field details.

___

Next Steps
----------

Now that you understand behavioral analysis decorators, explore other security features:

- **[Advanced Decorators](advanced.md)** - Time windows and detection controls
- **[Access Control Decorators](access-control.md)** - IP and geographic restrictions
- **[Content Filtering](content-filtering.md)** - Request validation and filtering
- **[Rate Limiting Decorators](rate-limiting.md)** - Traditional rate limiting

For complete API reference, see the [Behavioral Analysis API Documentation](../../api/decorators.md#behavioralmixin).
