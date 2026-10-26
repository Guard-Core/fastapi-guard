from __future__ import annotations

from guard_core.handlers import ipban_handler
from guard_core.handlers.ipban_handler import (
    IPBanManager,
    ip_ban_manager,
    ip_ban_manager_for,
)
from guard_core.models import SecurityConfig

from tests.redis_isolation import REDIS_URL


def _redis_config(prefix: str) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_penetration_detection=False,
    )


async def test_a_second_app_on_another_prefix_takes_the_class_singleton() -> None:
    first, second = _redis_config("wp186a:"), _redis_config("wp186b:")
    assert ip_ban_manager_for(first, bind=True) is ip_ban_manager
    own = ip_ban_manager_for(second, bind=True)
    assert own is not ip_ban_manager
    await own.initialize_redis(None)
    assert IPBanManager() is own


async def test_the_reset_after_it_gives_the_default_manager_back() -> None:
    assert IPBanManager() is ip_ban_manager
    assert ipban_handler.ip_ban_manager is ip_ban_manager
