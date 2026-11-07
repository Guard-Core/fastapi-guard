import threading
from collections.abc import Iterator

import pytest

from tests import thread_guard


@pytest.fixture
def parked_thread() -> Iterator[threading.Event]:
    release = threading.Event()
    thread = threading.Thread(target=release.wait, name="wp473-parked", daemon=False)
    thread.start()
    yield release
    release.set()
    thread.join()


@pytest.mark.usefixtures("parked_thread")
def test_a_thread_started_by_a_test_and_still_alive_is_named(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(thread_guard, "_GRACE_SECONDS", 0.0)
    assert "wp473-parked (daemon=False)" in thread_guard.leaked_threads()


def test_a_thread_that_has_finished_is_not_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(thread_guard, "_GRACE_SECONDS", 0.0)
    thread = threading.Thread(target=lambda: None, name="wp473-finished")
    thread.start()
    thread.join()
    assert not any("wp473-finished" in name for name in thread_guard.leaked_threads())


def test_an_idle_daemon_executor_thread_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(thread_guard, "_GRACE_SECONDS", 0.0)
    release = threading.Event()
    thread = threading.Thread(
        target=release.wait, name="ThreadPoolExecutor-99_0", daemon=True
    )
    thread.start()
    try:
        leaked = thread_guard.leaked_threads()
        assert any("ThreadPoolExecutor-99_0" in name for name in leaked)
    finally:
        release.set()
        thread.join()


def test_a_plain_daemon_thread_is_not_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(thread_guard, "_GRACE_SECONDS", 0.0)
    release = threading.Event()
    thread = threading.Thread(target=release.wait, name="wp473-daemon", daemon=True)
    thread.start()
    try:
        assert not any("wp473-daemon" in n for n in thread_guard.leaked_threads())
    finally:
        release.set()
        thread.join()


def test_stopping_the_shared_regex_pools_leaves_no_worker_thread() -> None:
    from guard_core.detection_engine import compiler

    compiler.shared_regex_executor().submit(int).result()
    assert any(t.name.startswith("guard-regex") for t in threading.enumerate())

    thread_guard.stop_the_shared_regex_pools()

    assert not any(t.name.startswith("guard-regex") for t in threading.enumerate())
    compiler._shared_executor = None
