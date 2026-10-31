---

title: Content Filtering Decorators - FastAPI Guard
description: Learn how to use content filtering decorators for request validation, content type filtering, and size limits
keywords: content filtering, request validation, content types, size limits, user agent blocking
---

Content Filtering Decorators
============================

Content filtering decorators allow you to control and validate incoming requests based on content type, size, user agents, referrers, and custom validation logic. These decorators help ensure your endpoints receive only the expected types of requests.

___

Content Type Filtering
----------------------

Control which content types are accepted by specific endpoints:

. Basic Content Type Restriction
------------------------------

```python
from guard import SecurityDecorator

guard_deco = SecurityDecorator(config)


@app.post("/api/json-only")
@guard_deco.content_type_filter(["application/json"])
def json_only_endpoint(data: dict):
    return {"received": data, "type": "json"}
```

. Multiple Content Types
----------------------

```python
@app.post("/api/flexible")
@guard_deco.content_type_filter(
    ["application/json", "application/x-www-form-urlencoded", "text/plain"]
)
def flexible_endpoint():
    return {"message": "Multiple content types accepted"}
```

. Image Upload Endpoints
----------------------

```python
@app.post("/api/upload/image")
@guard_deco.content_type_filter(["image/jpeg", "image/png", "image/gif", "image/webp"])
def image_upload():
    return {"status": "Image upload endpoint"}


@app.post("/api/upload/avatar")
@guard_deco.content_type_filter(["image/jpeg", "image/png"])
def avatar_upload():
    return {"status": "Avatar upload - JPEG/PNG only"}
```

___

Request Size Limits
-------------------

Control the maximum size of incoming requests:

. Basic Size Limits
-----------------

```python
@app.post("/api/upload/small")
@guard_deco.max_request_size(1024 * 1024)  # 1MB limit
def small_upload():
    return {"status": "Small file upload"}


@app.post("/api/upload/large")
@guard_deco.max_request_size(50 * 1024 * 1024)  # 50MB limit
def large_upload():
    return {"status": "Large file upload"}
```

. Size Limits with Content Types
-----------------------------

```python
@app.post("/api/upload/document")
@guard_deco.content_type_filter(["application/pdf", "text/plain"])
@guard_deco.max_request_size(10 * 1024 * 1024)  # 10MB for documents
def document_upload():
    return {"status": "Document uploaded"}


@app.post("/api/upload/media")
@guard_deco.content_type_filter(["video/mp4", "audio/mpeg"])
@guard_deco.max_request_size(100 * 1024 * 1024)  # 100MB for media
def media_upload():
    return {"status": "Media uploaded"}
```

. Progressive Size Limits
-----------------------

```python
# Different limits for different user tiers
@app.post("/api/upload/basic")
@guard_deco.max_request_size(1024 * 1024)  # 1MB for basic users
def basic_upload():
    return {"tier": "basic", "limit": "1MB"}


@app.post("/api/upload/premium")
@guard_deco.max_request_size(10 * 1024 * 1024)  # 10MB for premium
def premium_upload():
    return {"tier": "premium", "limit": "10MB"}


@app.post("/api/upload/enterprise")
@guard_deco.max_request_size(100 * 1024 * 1024)  # 100MB for enterprise
def enterprise_upload():
    return {"tier": "enterprise", "limit": "100MB"}
```

___

User Agent Blocking
-------------------

Block specific user agent patterns for individual routes:

. Block Bot User Agents
---------------------

```python
@app.get("/api/human-only")
@guard_deco.block_user_agents([r"bot", r"crawler", r"spider", r"scraper"])
def human_only_endpoint():
    return {"message": "Human users only"}
```

. Block Specific Tools
--------------------

```python
@app.get("/api/no-automation")
@guard_deco.block_user_agents(
    [
        r"curl.*",
        r"wget.*",
        r"Python-urllib.*",
        r"Python-requests.*",
        r"PostmanRuntime.*",
    ]
)
def no_automation_endpoint():
    return {"message": "No automation tools"}
```

. Block Malicious User Agents
---------------------------

```python
@app.get("/api/secure")
@guard_deco.block_user_agents(
    [
        r"sqlmap",
        r"nikto",
        r"nmap",
        r"masscan",
        r"nessus",
        r"burp",
    ]
)
def secure_endpoint():
    return {"data": "Protected from security scanners"}
```

___

Referrer Requirements
--------------------

Require requests to come from specific referrer domains:

. Basic Referrer Validation
-------------------------

```python
@app.get("/api/internal")
@guard_deco.require_referrer(["myapp.com", "app.mycompany.com"])
def internal_api():
    return {"message": "Internal API access"}
```

. Multiple Domain Support
-----------------------

```python
@app.get("/api/partner")
@guard_deco.require_referrer(
    ["partner1.com", "partner2.com", "api.partner3.com", "subdomain.partner4.com"]
)
def partner_api():
    return {"data": "Partner API access"}
```

. Development vs Production Referrers
-----------------------------------

```python
@app.get("/api/dev")
@guard_deco.require_referrer(["localhost:3000", "127.0.0.1:3000", "dev.myapp.com"])
def development_api():
    return {"env": "development"}


@app.get("/api/prod")
@guard_deco.require_referrer(["myapp.com", "www.myapp.com"])
def production_api():
    return {"env": "production"}
```

___

Custom Validation
-----------------

Add custom validation logic for complex requirements:

. Header Validation
-----------------

```python
from fastapi import Request, Response


async def validate_api_version(request: Request) -> Response | None:
    """Validate API version header."""
    version = request.headers.get("API-Version")
    if not version:
        return Response("Missing API-Version header", status_code=400)

    if version not in ["1.0", "2.0", "2.1"]:
        return Response("Unsupported API version", status_code=400)

    return None


@app.get("/api/versioned")
@guard_deco.custom_validation(validate_api_version)
def versioned_endpoint():
    return {"message": "Version validated"}
```

. Request Body Validation
-----------------------

```python
async def validate_json_structure(request: Request) -> Response | None:
    """Validate JSON request structure."""
    if request.method in ["POST", "PUT", "PATCH"]:
        try:
            if "application/json" in request.headers.get("content-type", ""):
                body = await request.json()

                # Require specific fields
                required_fields = ["user_id", "action", "timestamp"]
                for field in required_fields:
                    if field not in body:
                        return Response(
                            f"Missing required field: {field}", status_code=400
                        )

                # Validate field types
                if not isinstance(body.get("user_id"), int):
                    return Response("user_id must be integer", status_code=400)

        except Exception:
            return Response("Invalid JSON", status_code=400)

    return None


@app.post("/api/structured")
@guard_deco.custom_validation(validate_json_structure)
def structured_endpoint():
    return {"status": "Structure validated"}
```

. Authentication Token Validation
-------------------------------

```python
async def validate_bearer_token(request: Request) -> Response | None:
    """Validate Bearer token format."""
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return Response("Invalid authorization format", status_code=401)

    token = auth_header[7:]  # Remove "Bearer " prefix

    # Validate token format (example: JWT-like structure)
    if len(token.split(".")) != 3:
        return Response("Invalid token format", status_code=401)

    return None


@app.get("/api/token-validated")
@guard_deco.custom_validation(validate_bearer_token)
def token_validated_endpoint():
    return {"message": "Token format validated"}
```

___

Combining Content Filters
-------------------------

Stack multiple content filtering decorators for comprehensive validation:

. Complete Upload Endpoint
------------------------

```python
@app.post("/api/upload/complete")
@guard_deco.content_type_filter(["image/jpeg", "image/png"])
@guard_deco.max_request_size(5 * 1024 * 1024)  # 5MB limit
@guard_deco.require_referrer(["myapp.com"])
@guard_deco.block_user_agents([r"bot", r"curl.*"])
def complete_upload():
    return {"status": "All validations passed"}
```

. API Gateway Pattern
-------------------

```python
# Public API - Basic filtering
@app.post("/api/public/data")
@guard_deco.content_type_filter(["application/json"])
@guard_deco.max_request_size(1024 * 1024)  # 1MB
def public_api():
    return {"tier": "public"}


# Partner API - Medium filtering
@app.post("/api/partner/data")
@guard_deco.content_type_filter(["application/json", "application/xml"])
@guard_deco.max_request_size(10 * 1024 * 1024)  # 10MB
@guard_deco.require_referrer(["partner.com"])
def partner_api():
    return {"tier": "partner"}


# Internal API - Strict filtering
@app.post("/api/internal/data")
@guard_deco.content_type_filter(["application/json"])
@guard_deco.max_request_size(50 * 1024 * 1024)  # 50MB
@guard_deco.require_referrer(["internal.mycompany.com"])
@guard_deco.block_user_agents([r"bot"])
def internal_api():
    return {"tier": "internal"}
```

___

Advanced Patterns
-----------------

. Content Type Based Routing
--------------------------

```python
@app.post("/api/data/json")
@guard_deco.content_type_filter(["application/json"])
def json_processor():
    return {"processor": "json"}


@app.post("/api/data/xml")
@guard_deco.content_type_filter(["application/xml", "text/xml"])
def xml_processor():
    return {"processor": "xml"}


@app.post("/api/data/form")
@guard_deco.content_type_filter(["application/x-www-form-urlencoded"])
def form_processor():
    return {"processor": "form"}
```

. Size-Based Processing
---------------------

```python
@app.post("/api/process/small")
@guard_deco.max_request_size(1024 * 1024)  # 1MB - fast processing
def small_processor():
    return {"processing": "fast", "queue": "immediate"}


@app.post("/api/process/medium")
@guard_deco.max_request_size(10 * 1024 * 1024)  # 10MB - normal processing
def medium_processor():
    return {"processing": "normal", "queue": "standard"}


@app.post("/api/process/large")
@guard_deco.max_request_size(100 * 1024 * 1024)  # 100MB - slow processing
def large_processor():
    return {"processing": "slow", "queue": "background"}
```

___

Error Handling
--------------

Content filtering decorators return specific HTTP status codes:

- **400 Bad Request**: Missing required headers, invalid content
- **413 Payload Too Large**: Request size exceeds limit
- **415 Unsupported Media Type**: Content type not allowed
- **403 Forbidden**: User agent blocked, referrer not allowed

. Custom Error Messages
---------------------

```python
config = SecurityConfig(
    custom_error_responses={
        400: "Request validation failed",
        413: "File too large for this endpoint",
        415: "Content type not supported",
        403: "Request source not authorized",
    }
)
```

___

Best Practices
--------------

. Layer Content Controls
----------------------

Apply multiple content filters for defense in depth:

```python
@guard_deco.content_type_filter(["application/json"])  # Only JSON
@guard_deco.max_request_size(1024 * 1024)             # Size limit
@guard_deco.require_referrer(["myapp.com"])           # Trusted source
@guard_deco.block_user_agents([r"bot"])           # No bots
```

. Match Limits to Functionality
-----------------------------

Set appropriate size limits based on expected use:

```python
# Text API - small limit
@guard_deco.max_request_size(64 * 1024)  # 64KB

# Image upload - medium limit
@guard_deco.max_request_size(5 * 1024 * 1024)  # 5MB

# Video upload - large limit
@guard_deco.max_request_size(100 * 1024 * 1024)  # 100MB
```

. Use Specific Content Type Lists
------------------------------

Be explicit about allowed content types:

```python
# Good: Specific types
@guard_deco.content_type_filter(["image/jpeg", "image/png"])

# Avoid: Too permissive
# @guard_deco.content_type_filter(["*/*"])
```

. Validate Referrers Carefully
----------------------------

Include all legitimate sources:

```python
@guard_deco.require_referrer([
    "myapp.com",
    "www.myapp.com",
    "app.myapp.com",
    "mobile.myapp.com"  # Don't forget mobile subdomain
])
```

___

Testing Content Filters
-----------------------

Test your content filtering decorators:

```python
import pytest
from fastapi.testclient import TestClient


def test_content_type_filter():
    # Should reject wrong content type
    response = client.post(
        "/api/json-only", data="plain text", headers={"Content-Type": "text/plain"}
    )
    assert response.status_code == 415

    # Should accept correct content type
    response = client.post(
        "/api/json-only",
        json={"data": "test"},
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200


def test_size_limit():
    # Should reject large request
    large_data = "x" * (2 * 1024 * 1024)  # 2MB
    response = client.post(
        "/api/small-upload",  # 1MB limit
        data=large_data,
    )
    assert response.status_code == 413


def test_user_agent_block():
    # Should block bot user agent
    response = client.get("/api/human-only", headers={"User-Agent": "GoogleBot/1.0"})
    assert response.status_code == 403
```

___

Next Steps
----------

Now that you understand content filtering decorators, explore other security features:

- **[Advanced Decorators](advanced.md)** - Time windows and detection controls
- **[Behavioral Analysis](behavioral.md)** - Monitor usage patterns
- **[Access Control Decorators](access-control.md)** - IP and geographic restrictions
- **[Authentication Decorators](authentication.md)** - HTTPS and auth requirements

For complete API reference, see the [Content Filtering API Documentation](../../api/decorators.md#contentfilteringmixin).
