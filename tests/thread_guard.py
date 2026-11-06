import sys
import threading
import time

_EXECUTOR_THREAD_PREFIXES = ("ThreadPoolExecutor", "asyncio_")
_GRACE_SECONDS = 3.0
_SETTLE_STEP_SECONDS = 0.05

_started_before_the_tests: frozenset[int] = frozenset()


def install() -> None:
    global _started_before_the_tests
    _started_before_the_tests = frozenset(
        thread.ident for thread in threading.enumerate() if thread.ident is not None
    )


def _outlives_the_session(thread: threading.Thread) -> bool:
    if thread is threading.main_thread() or not thread.is_alive():
        return False
    if thread.ident in _started_before_the_tests:
        return False
    return not thread.daemon or thread.name.startswith(_EXECUTOR_THREAD_PREFIXES)


def leaked_threads() -> list[str]:
    deadline = time.monotonic() + _GRACE_SECONDS
    while True:
        leaked = [t for t in threading.enumerate() if _outlives_the_session(t)]
        if not leaked or time.monotonic() >= deadline:
            return [f"{t.name} (daemon={t.daemon})" for t in leaked]
        time.sleep(_SETTLE_STEP_SECONDS)


_REGEX_COMPILER_MODULES = (
    "guard_core.detection_engine.compiler",
    "guard_core.sync.detection_engine.compiler",
)


def stop_the_shared_regex_pools() -> None:
    for name in _REGEX_COMPILER_MODULES:
        pool = getattr(sys.modules.get(name), "_shared_executor", None)
        if pool is not None:
            pool.shutdown(wait=True)
