from __future__ import annotations

import time

from guard_core.handlers import ipban_handler
from guard_core.handlers.ipban_handler import (
    IPBanManager,
    ip_ban_manager,
    ip_ban_manager_for,
)
from guard_core.models import SecurityConfig

from tests.redis_isolation import REDIS_URL, suite_redis_prefix


def _redis_config(prefix: str) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_penetration_detection=False,
    )


async def test_a_second_prefix_app_leaves_the_default_manager_as_singleton() -> None:
    first = _redis_config(suite_redis_prefix("wp186a"))
    second = _redis_config(suite_redis_prefix("wp186b"))
    assert ip_ban_manager_for(first, bind=True) is ip_ban_manager
    own = ip_ban_manager_for(second, bind=True)
    assert own is not ip_ban_manager
    await own.initialize_redis(None)
    assert IPBanManager() is ip_ban_manager
    ip_ban_manager.banned_ips["203.0.113.9"] = time.time() + 60


async def test_the_reset_after_it_cleared_the_default_manager() -> None:
    assert IPBanManager() is ip_ban_manager
    assert ipban_handler.ip_ban_manager is ip_ban_manager
    assert "203.0.113.9" not in ip_ban_manager.banned_ips
