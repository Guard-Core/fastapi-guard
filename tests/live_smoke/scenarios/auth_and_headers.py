from datetime import datetime, timezone

from tests.live_smoke.driver import ScenarioContext
from tests.live_smoke.registry import scenario

EXCLUDED_HEADERS = ["x-real-ip", "x-forwarded-for"]

AUTH_BASE_CONFIG = {"excluded_detection_headers": EXCLUDED_HEADERS}


@scenario(covers={"require_headers"}, config=AUTH_BASE_CONFIG)
def require_headers_decorator_enforces_exact_values(ctx: ScenarioContext) -> None:
    client = ctx.client

    missing = client.get("/auth/custom-headers")
    assert missing.status_code == 400

    mismatched = client.get(
        "/auth/custom-headers",
        headers={"X-Custom-Header": "wrong-value", "X-Client-ID": "required-value"},
    )
    assert mismatched.status_code == 400

    matched = client.get(
        "/auth/custom-headers",
        headers={
            "X-Custom-Header": "required-value",
            "X-Client-ID": "required-value",
        },
    )
    assert matched.status_code == 200


@scenario(
    covers={"api_key_auth", "required_headers", "authentication"},
    config=AUTH_BASE_CONFIG,
)
def api_key_auth_refuses_a_missing_key_and_answers_a_present_one(
    ctx: ScenarioContext,
) -> None:
    client = ctx.client

    missing = client.get("/auth/api-key")
    assert missing.status_code in (400, 401)

    present = client.get(
        "/auth/api-key", headers={"X-API-Key": "smoke-arbitrary-value"}
    )
    assert present.status_code == 200


@scenario(covers={"auth_verifier", "authentication"}, config=AUTH_BASE_CONFIG)
def bearer_auth_uses_the_configured_auth_verifier(ctx: ScenarioContext) -> None:
    client = ctx.client

    missing = client.get("/auth/bearer-auth")
    assert missing.status_code == 401

    present = client.get(
        "/auth/bearer-auth", headers={"Authorization": "Bearer smoke-token"}
    )
    assert present.status_code == 200


@scenario(covers={"require_referrer", "referrer"}, config=AUTH_BASE_CONFIG)
def require_referrer_enforces_scheme_prefixed_origins(ctx: ScenarioContext) -> None:
    client = ctx.client

    missing = client.get("/content/referrer-check")
    assert missing.status_code == 403

    invalid = client.get(
        "/content/referrer-check", headers={"Referer": "https://evil.example"}
    )
    assert invalid.status_code == 403

    valid = client.get(
        "/content/referrer-check", headers={"Referer": "https://example.com/page"}
    )
    assert valid.status_code == 200


def _business_hours_expected_status() -> int:
    current = datetime.now(timezone.utc).strftime("%H:%M")
    return 200 if "09:00" <= current <= "17:00" else 403


@scenario(covers={"time_window"}, config=AUTH_BASE_CONFIG)
def time_window_restricts_access_to_business_hours(ctx: ScenarioContext) -> None:
    response = ctx.client.get("/advanced/business-hours")
    assert response.status_code == _business_hours_expected_status()


HTTPS_CONFIG = {"enforce_https": True, "excluded_detection_headers": EXCLUDED_HEADERS}


@scenario(covers={"https_enforcement", "require_https"}, config=HTTPS_CONFIG)
def https_enforcement_redirects_plain_http_requests(ctx: ScenarioContext) -> None:
    client = ctx.client

    global_redirect = client.get("/basic/ip", params={"q": "hello"})
    assert global_redirect.status_code == 301

    decorator_redirect = client.get("/auth/https-only")
    assert decorator_redirect.status_code == 301
