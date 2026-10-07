import httpx

from tests.live_smoke.driver import ScenarioContext
from tests.live_smoke.registry import scenario

_BASE = {
    "auto_ban_threshold": 1000,
    "rate_limit": 1000,
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
}

_XSS = "<script>alert(1)</script>"
_SQLI = "' UNION SELECT password FROM admin--"

_CACHE_PATH = "/tmp/guard-core-pattern-validation-cache.json"


def _echo(client: httpx.Client, body: dict[str, object]) -> httpx.Response:
    return client.post("/basic/echo", json=body)


@scenario(
    covers={"detection_pattern_validation_cache_path"},
    config={**_BASE, "detection_pattern_validation_cache_path": _CACHE_PATH},
)
def detection_pattern_validation_cache_path_enabled(ctx: ScenarioContext) -> None:
    first = _echo(ctx.client, {"note": "benign payload"})
    assert first.status_code == 200, (
        "detection_pattern_validation_cache_path set still blocked a benign payload: "
        f"{first.status_code}"
    )

    attack = _echo(ctx.client, {"note": _XSS, "query": _SQLI})
    assert attack.status_code == 400, (
        "detection_pattern_validation_cache_path set stopped blocking an attack payload: "
        f"{attack.status_code}"
    )

    repeat = _echo(ctx.client, {"note": _XSS, "query": _SQLI})
    assert repeat.status_code == 400, (
        "repeated attack payload was not handled consistently with the validation cache on: "
        f"{repeat.status_code}"
    )
