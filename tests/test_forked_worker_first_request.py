import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# The parent serves requests (its regex worker threads start), pauses, and forks;
# the child serves the same requests through the same app. A fresh interpreter keeps
# the test process, with its own threads and loop, from being forked.
_SCRIPT = """
import ast, asyncio, os, time, logging, warnings
warnings.simplefilter("ignore"); logging.disable(logging.CRITICAL)
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from guard import SecurityConfig, SecurityMiddleware
from guard_core.handlers.suspatterns_handler import active_sus_patterns

config = SecurityConfig(enable_redis=False, enable_rate_limiting=False)
app = FastAPI()

@app.get("/p")
async def probe() -> dict:
    return {"ok": True}

app.add_middleware(SecurityMiddleware, config=config)
texts = ("hello world", "zz-foo12bar-zz", "x' UNION SELECT password FROM users--")

async def statuses():
    transport = ASGITransport(app=app, client=("203.0.113.9", 5000))
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        answers = [await client.get("/p", params={"q": text}) for text in texts]
        return [answer.status_code for answer in answers]

parent = asyncio.run(statuses())
asyncio.run(active_sus_patterns().add_pattern(r"foo\\d+bar", True))
parent = asyncio.run(statuses())
time.sleep(0.3)
reader, writer = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(reader)
    os.write(writer, repr(asyncio.run(statuses())).encode())
    os._exit(0)
os.close(writer)
child = ast.literal_eval(os.read(reader, 65536).decode())
os.waitpid(pid, 0)
print(repr((parent, child)))
"""


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_a_forked_worker_answers_its_first_requests_like_its_parent() -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"
    result = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", _SCRIPT],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=True,
    )
    parent, child = ast.literal_eval(result.stdout.strip().splitlines()[-1])

    assert parent[0] == 200
    assert parent[1:] == [400, 400]
    assert child == parent
