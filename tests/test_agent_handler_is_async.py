import inspect

from fastapi import FastAPI
from guard_agent import GuardAgentHandler
from guard_core.models import SecurityConfig

from guard.middleware import SecurityMiddleware


def test_a_middleware_built_outside_any_loop_holds_the_async_agent_handler() -> None:
    config = SecurityConfig(
        enable_redis=False, enable_agent=True, agent_api_key="sk-test-0123456789"
    )

    middleware = SecurityMiddleware(FastAPI(), config=config)

    assert isinstance(middleware.agent_handler, GuardAgentHandler)
    assert inspect.iscoroutinefunction(middleware.agent_handler.start)
    assert inspect.iscoroutinefunction(middleware.agent_handler.stop)
