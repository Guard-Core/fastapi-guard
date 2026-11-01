---

title: Advanced Security Decorators - FastAPI Guard
description: Learn how to use advanced security decorators for time-based access, honeypot detection, and suspicious pattern control.
keywords: advanced security, time window, honeypot, suspicious patterns, security decorators
---

Advanced Security Decorators
============================

Advanced security decorators offer sophisticated controls for fine-tuning your application's security posture. These decorators allow you to implement time-based access rules, set up honeypots to trap malicious bots, and control suspicious pattern detection on a per-route basis.

___

Time-Based Access Control
-------------------------

Restrict access to endpoints based on specific time windows. This is useful for APIs that should only be available during business hours or maintenance periods.

. Restrict to Business Hours
--------------------------

```python
from guard import SecurityDecorator

guard_deco = SecurityDecorator(config)


@app.get("/api/reports")
@guard_deco.time_window("09:00", "17:00", "EST")
def generate_reports():
    return {
        "message": "Reports are only available during business hours (9 AM - 5 PM EST)"
    }
```

. Maintenance Window
------------------

Only allow access during a specific maintenance window.

```python
@app.post("/api/maintenance")
@guard_deco.time_window("01:00", "03:00", "UTC")
def perform_maintenance():
    return {"status": "Maintenance operations running"}
```

___

Honeypot Protection
-------------------

Set up "honeypot" fields in your forms or JSON payloads to detect and block bots. These fields are hidden from human users but are often filled out by automated scripts.

. Basic Honeypot
--------------

Add a honeypot field to a registration form. If a bot fills it, access is denied.

```python
@app.post("/register")
@guard_deco.honeypot_detection(trap_fields=["website_url"])
def register_user(form_data: dict):
    # This field should be hidden via CSS for real users
    return {"message": "User registered successfully"}
```

*In your frontend, you would hide the `website_url` field, for example, with `style="display:none"`.*

. Multiple Honeypot Fields
------------------------

Use multiple fields to increase the chances of trapping a bot.

```python
@app.post("/contact")
@guard_deco.honeypot_detection(trap_fields=["comments", "phone_number_alt"])
def contact_form(form_data: dict):
    return {"status": "Message sent"}
```

. JSON Payload Honeypot
-----------------------

Honeypots also work with JSON request bodies.

```python
@app.post("/api/subscribe")
@guard_deco.honeypot_detection(trap_fields=["user_nickname"])
def subscribe_newsletter(payload: dict):
    return {"message": "Subscribed successfully"}
```

___

Suspicious Pattern Detection Control
------------------------------------

Globally, FastAPI Guard may be configured to detect suspicious patterns in requests. This decorator allows you to override that setting for specific endpoints where the global rules may not be appropriate.

. Disable Detection for a Specific Route
--------------------------------------

If an endpoint accepts data that might trigger false positives (e.g., code snippets, complex user-generated content), you can disable suspicious pattern detection for it.

```python
@app.post("/api/code-submission")
@guard_deco.suspicious_detection(enabled=False)
def submit_code(code: str):
    # This endpoint is safe from pattern detection false positives
    return {"status": "Code submitted for review"}
```

. Explicitly Enable Detection
---------------------------

While detection is often enabled by default, you can use this decorator to make it explicit, improving code readability.

```python
@app.get("/api/search")
@guard_deco.suspicious_detection(enabled=True)
def search(query: str):
    return {"results": "Search results for your query"}
```

. Exclude a Single Parameter
--------------------------

When one field is the only false positive, keep detection on and exclude just that field. An OAuth `redirect_uri` is the usual case: on `/authorize` it carries a full URL, and for native and MCP clients a loopback one, which the `ssrf` category matches.

```python
@guard_deco.detection_exclusion(params={"redirect_uri"})
@app.get("/oauth/authorize")
def authorize(redirect_uri: str):
    return {"status": "redirecting"}
```

`headers` and `body_fields` take the same shape. The global equivalents are `excluded_detection_params`, `excluded_detection_headers` and `excluded_detection_body_fields` on `SecurityConfig`. Headers that carry URLs, such as `referer` and `origin`, are the usual header case: excluding one stops its semantic analysis but leaves the pattern-based checks running against it.

___

Combining Advanced Decorators
-----------------------------

You can stack advanced decorators with each other and with other security decorators for robust, layered security.

. High-Security Endpoint
----------------------

This endpoint is only accessible during specific hours and is protected by a honeypot.

```python
@app.post("/api/admin/config")
@guard_deco.time_window("10:00", "16:00", "UTC")
@guard_deco.honeypot_detection(trap_fields=["admin_email_confirm"])
@guard_deco.require_auth(type="bearer")  # From authentication decorators
def update_admin_config(config_data: dict):
    return {"status": "Configuration updated"}
```

___

Error Handling
--------------

Advanced decorators integrate with the middleware's error handling:

- **403 Forbidden**:
  - When a request is outside the allowed `time_window`.
  - When a `honeypot_detection` field is filled.

. Custom Error Messages
---------------------

You can configure custom error messages in the `SecurityConfig`.

```python
config = SecurityConfig(
    custom_error_responses={
        403: "Access denied. Please check access times and ensure you are not a bot."
    }
)
```

___

Best Practices
--------------

. Use Timezones Explicitly
------------------------

Always specify the timezone in `time_window` to avoid ambiguity, especially for applications serving a global user base.

```python
# Good: Explicit timezone
@guard_deco.time_window("09:00", "17:00", "America/New_York")

# Avoid: Relying on default UTC if your users are in different timezones
# @guard_deco.time_window("09:00", "17:00")
```

. Hide Honeypot Fields Effectively
--------------------------------

Ensure honeypot fields are truly hidden from human users using CSS or other frontend techniques. A visible honeypot field can confuse users and defeat its purpose.

. Be Strategic with Detection Control
-------------------------------------

Only disable `suspicious_detection` when necessary. Disabling it globally or on many endpoints can weaken your application's defenses against penetration attempts.

___

Next Steps
----------

Now that you've learned about advanced decorators, you can explore other decorators to build a comprehensive security strategy:

- **[Behavioral Analysis Decorators](behavioral.md)** - Monitor usage patterns and detect anomalies.
- **[Content Filtering](content-filtering.md)** - Validate and sanitize request data.
- **[Rate Limiting Decorators](rate-limiting.md)** - Protect against brute-force and denial-of-service attacks.

For complete API reference, see the [Advanced Decorators API Documentation](../../api/decorators.md#advancedmixin).
