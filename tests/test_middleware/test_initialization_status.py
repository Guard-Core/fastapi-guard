import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from guard_core.core.initialization import HandlerInitializer
from guard_core.models import SecurityConfig

from guard.middleware import SecurityMiddleware

if not hasattr(HandlerInitializer, "get_initialization_status"):
    pytest.skip(
        "requires guard-core>=3.8.0 (HandlerInitializer.get_initialization_status)",
        allow_module_level=True,
    )


def test_get_initialization_status_returns_upstream_structure() -> None:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=config)

    status = middleware.get_initialization_status()

    assert "cloud_providers" in status
    assert "geo_ip" in status
    assert isinstance(status["cloud_providers"], dict)


def test_get_initialization_status_geo_ip_is_none_without_handler() -> None:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=config)

    status = middleware.get_initialization_status()

    assert status["geo_ip"] is None


def test_get_initialization_status_serializes_datetimes() -> None:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=config)

    refreshed_at = datetime(2026, 7, 31, 12, 0, 0, tzinfo=timezone.utc)
    middleware.handler_initializer = MagicMock()
    middleware.handler_initializer.get_initialization_status.return_value = {
        "cloud_providers": {
            "AWS": {"ready": True, "last_refreshed": refreshed_at, "entries": 3421},
        },
        "geo_ip": {"ready": True, "last_refreshed": refreshed_at, "entries": 494},
    }

    status = json.loads(json.dumps(middleware.get_initialization_status()))

    encoded = json.dumps(status)
    assert "2026-07-31" in encoded
    assert (
        status["cloud_providers"]["AWS"]["last_refreshed"] == refreshed_at.isoformat()
    )
    assert status["geo_ip"]["last_refreshed"] == refreshed_at.isoformat()
