import logging
from typing import Any
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from guard_core.exceptions import AgentPackageNotInstalledError
from guard_core.models import SecurityConfig

from guard.middleware import SecurityMiddleware


def _config(**kwargs: Any) -> SecurityConfig:
    return SecurityConfig(enable_agent=True, agent_api_key="0123456789abcdef", **kwargs)


async def test_missing_agent_package_fails_soft_with_clear_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = FastAPI()
    config = _config()
    with patch.object(
        SecurityConfig,
        "to_agent_config",
        side_effect=AgentPackageNotInstalledError("nope"),
    ):
        with caplog.at_level(logging.ERROR):
            middleware = SecurityMiddleware(app, config=config)

    assert middleware.agent_handler is None
    assert middleware.agent_degraded is True
    assert any("pip install fastapi-guard[agent]" in r.message for r in caplog.records)


async def test_missing_agent_package_strict_raises() -> None:
    app = FastAPI()
    config = _config(agent_strict=True)
    with patch.object(
        SecurityConfig,
        "to_agent_config",
        side_effect=AgentPackageNotInstalledError("nope"),
    ):
        with pytest.raises(AgentPackageNotInstalledError):
            SecurityMiddleware(app, config=config)


async def test_agent_init_failure_fires_on_error_hook() -> None:
    app = FastAPI()
    captured: list[tuple[str, BaseException, dict[str, Any]]] = []
    config = _config(on_error=lambda s, e, c: captured.append((s, e, c)))
    err = AgentPackageNotInstalledError("nope")
    with patch.object(SecurityConfig, "to_agent_config", side_effect=err):
        SecurityMiddleware(app, config=config)

    assert captured[0][0] == "agent_init"
    assert captured[0][1] is err


async def test_agent_stats_reports_degraded_after_init_failure() -> None:
    app = FastAPI()
    config = _config()
    with patch.object(
        SecurityConfig,
        "to_agent_config",
        side_effect=AgentPackageNotInstalledError("nope"),
    ):
        middleware = SecurityMiddleware(app, config=config)

    assert middleware.agent_stats == {"enabled": False, "degraded": True}


async def test_generic_agent_init_failure_fails_soft(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = FastAPI()
    config = _config()
    with patch.object(
        SecurityConfig, "to_agent_config", side_effect=RuntimeError("boom")
    ):
        with caplog.at_level(logging.ERROR):
            middleware = SecurityMiddleware(app, config=config)

    assert middleware.agent_handler is None
    assert middleware.agent_degraded is True
    assert any("Failed to initialize Guard Agent" in r.message for r in caplog.records)
