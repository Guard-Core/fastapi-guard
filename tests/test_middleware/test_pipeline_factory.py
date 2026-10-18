from fastapi import FastAPI
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

from guard import SecurityDecorator
from guard.middleware import SecurityMiddleware


async def _custom_check(request: GuardRequest) -> GuardResponse | None:
    return None


def _fully_enabled_config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        emergency_mode=True,
        enforce_https=True,
        log_request_level="INFO",
        block_cloud_providers=frozenset({"AWS"}),
        blocked_user_agents=["badbot"],
        custom_request_check=_custom_check,
    )


async def test_middleware_builds_pipeline_via_factory() -> None:
    app = FastAPI()
    config = _fully_enabled_config()
    decorator = SecurityDecorator(config)

    @decorator.max_request_size(1000)
    @decorator.require_headers({"X-Api-Key": "required"})
    @decorator.require_auth()
    @decorator.require_referrer(["example.com"])
    @decorator.custom_validation(_custom_check)
    @decorator.time_window("00:00", "23:59")
    @app.get("/fully-enabled")
    async def fully_enabled_endpoint() -> dict[str, str]:
        return {"message": "ok"}

    middleware = SecurityMiddleware(app, config=config)
    middleware.set_decorator_handler(decorator)

    middleware._build_security_pipeline()

    assert middleware.security_pipeline is not None
    check_names = middleware.security_pipeline.get_check_names()
    assert len(check_names) == 18
    assert "cors_preflight" in check_names
    assert "ip_security" in check_names
    assert "rate_limit" in check_names
    assert "suspicious_activity" in check_names


def test_build_default_pipeline_symbol_is_importable() -> None:
    from guard_core.core.checks import build_default_pipeline

    assert callable(build_default_pipeline)
