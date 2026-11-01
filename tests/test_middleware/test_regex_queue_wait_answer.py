import concurrent.futures
import threading
from collections.abc import AsyncGenerator, Iterator

import pytest
from fastapi import FastAPI
from guard_core.detection_engine import compiler as compiler_module
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for
from httpx import ASGITransport, AsyncClient

from guard import SecurityConfig
from guard.middleware import SecurityMiddleware

CLIENT = ("203.0.113.9", 50000)
BUSY_ROW = "[xyz]7"


@pytest.fixture
def saturated_regex_pool(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    workers = compiler_module._SHARED_EXECUTOR_MAX_WORKERS
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    monkeypatch.setattr(compiler_module, "_shared_executor", pool)
    release = threading.Event()
    all_running = threading.Barrier(workers + 1)

    def hold() -> None:
        all_running.wait(10)
        release.wait(30)

    for _ in range(workers):
        pool.submit(hold)
    all_running.wait(10)
    yield
    release.set()
    pool.shutdown(wait=True)


@pytest.fixture
async def client_of_the_app() -> AsyncGenerator[AsyncClient, None]:
    config = SecurityConfig(
        enable_rate_limiting=False,
        enable_redis=False,
        enable_agent=False,
        fail_secure=True,
        detection_compiler_timeout=0.3,
        custom_error_responses={503: "Busy, retry shortly"},
    )
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/ping")
    async def ping() -> dict[str, bool]:
        return {"ok": True}

    async with AsyncClient(
        transport=ASGITransport(app=app, client=CLIENT), base_url="http://test"
    ) as client:
        assert (await client.get("/ping")).status_code == 200
        await sus_patterns_manager_for(config).add_pattern(BUSY_ROW, custom=True)
        yield client
        await sus_patterns_manager_for(config).remove_pattern(BUSY_ROW, custom=True)


@pytest.mark.usefixtures("saturated_regex_pool")
async def test_a_queue_wait_answers_503_with_retry_after_and_the_custom_message(
    client_of_the_app: AsyncClient,
) -> None:
    response = await client_of_the_app.get("/ping", params={"q": "hello"})

    assert response.status_code == 503
    assert response.headers["retry-after"] == "1"
    assert response.text == "Busy, retry shortly"


async def test_the_same_request_on_a_free_pool_passes(
    client_of_the_app: AsyncClient,
) -> None:
    response = await client_of_the_app.get("/ping", params={"q": "hello"})

    assert response.status_code == 200
