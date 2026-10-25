---

title: Custom Security Patterns - FastAPI Guard
description: Create and manage custom security patterns for detecting specific threats in your FastAPI application
keywords: security patterns, custom detection, threat patterns, security rules
---

Custom Patterns
===============

FastAPI Guard allows you to add custom patterns for detecting suspicious activity.

___

Adding Custom Patterns
-----------------------

Add your own patterns to the detection system:

```python
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for

# The module-level objects are the default app's. Take the ones of the app
# you act on with the config that app was built with.
patterns = sus_patterns_manager_for(security_config)


async def setup_patterns():
    # Add custom pattern
    await patterns.add_pattern(r"malicious_pattern.*", custom=True)
```

`add_pattern` checks the pattern for ReDoS safety before adding it. If the pattern is unsafe or malformed, it logs a warning and returns without adding the pattern or raising an exception.

___

Pattern Types
-------------

You can add patterns for different types of attacks:

```python
# Custom XSS pattern
await patterns.add_pattern(r"<script\s*src=.*>", custom=True)

# Custom SQL injection pattern
await patterns.add_pattern(r";\s*DROP\s+TABLE", custom=True)

# Custom file path pattern
await patterns.add_pattern(r"\.\.\/.*\/etc\/passwd", custom=True)
```

___

Managing Patterns
-----------------

Remove or modify existing patterns:

```python
# Remove a custom pattern
success = await patterns.remove_pattern(r"malicious_pattern.*", custom=True)
if success:
    print("Pattern removed successfully")
else:
    print("Pattern not found")

# Get all patterns (both default and custom)
all_patterns = await patterns.get_all_patterns()

# Get only default patterns
default_patterns = await patterns.get_default_patterns()

# Get only custom patterns
custom_patterns = await patterns.get_custom_patterns()

# Get all compiled patterns
all_compiled_patterns = await patterns.get_all_compiled_patterns()

# Get only default compiled patterns
default_compiled = await patterns.get_default_compiled_patterns()

# Get only custom compiled patterns
custom_compiled = await patterns.get_custom_compiled_patterns()
```

___

Pattern Testing
---------------

Test your patterns against requests:

```python
from guard_core.utils import detect_penetration_attempt


@app.post("/test/patterns")
async def test_patterns(request: Request):
    is_suspicious, trigger_info = await detect_penetration_attempt(request)
    return {
        "suspicious": is_suspicious,
        "trigger_info": trigger_info,
        "request_body": await request.body(),
    }
```
