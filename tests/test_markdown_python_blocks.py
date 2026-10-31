"""Every python block of every shipped Markdown file stays true to the installed API.

Per Markdown file, the python blocks run cumulatively in one namespace that starts
from PRELUDE (the names a page assumes the reader already has). A block may fail
only because the sandbox has no network, no server and no extra package; any other
exception means the page shows something the library rejects. After each block,
every call, keyword and attribute on a Guard object is checked against the live
signature, and every Guard import must resolve.
"""

import ast
import asyncio
import functools
import importlib
import inspect
import json
import logging
import pkgutil
import re
import signal
import socket
import subprocess
import sys
import warnings
from collections.abc import Callable, Iterator
from pathlib import Path
from types import CodeType, FrameType

import pytest
from guard_core.core.events.event_types import (
    CHECK_NAME_VALUES,
    EVENT_TYPE_VALUES,
    METRIC_TYPE_VALUES,
)
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig as ConfigModel
from pydantic.fields import FieldInfo

ROOT = Path(__file__).resolve().parents[1]
GUARD_ROOTS = ("guard_core", "guard", "guard_agent", "guardagent")
PLACEHOLDER_MODULE = re.compile(r"(^|\.)(my_|your_|some_)\w*$")
# Signature listings of a function the application implements, not the engine
USER_DEFINED_CONTRACTS = {"verifier"}
EXCLUDED_PARTS = {".git", ".github", ".venv", "node_modules", "site"}
FENCE = re.compile(r"^([ \t]*)```python[^\n]*\n(.*?)^\1```", re.DOTALL | re.MULTILINE)
SANDBOX_ERRORS = (NameError, ImportError, OSError, TimeoutError)
TOP_LEVEL_AWAIT = ast.PyCF_ALLOW_TOP_LEVEL_AWAIT
ENVIRONMENT: dict[str, str] = {
    "GUARD_API_KEY": "test-api-key",
    "GUARD_PROJECT_ID": "test-project",
    "GUARD_API_KEY_W_ENCRYPTION": "test-api-key",
    "GUARD_PROJECT_ENCRYPTION_KEY": "test-encryption-key",
}
PRELUDE = """
from typing import *
import dataclasses, ipaddress, json, logging, re, time
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass
from contextlib import contextmanager
from fastapi import FastAPI, Request, Response, HTTPException
from guard import *

app = FastAPI()
config = SecurityConfig(
    ipinfo_token="test-token",
    behavior_scan_response_body=True,
    enable_redis=True,
    redis_url="redis://localhost:6379",
)
security_config = config
guard_deco = SecurityDecorator(config)
redis_handler = RedisManager(config)
sus_patterns_handler.configure(config)


async def _teardown():
    for _manager in (ip_ban_manager, security_headers_manager, cloud_handler):
        _manager.redis_handler = None
    for _manager in (ip_ban_manager, security_headers_manager, cloud_handler):
        _manager.redis_handler = None
    await ip_ban_manager.reset()
    await security_headers_manager.reset()
    await sus_patterns_handler.reset()
"""
ALT_PRELUDE = """
from typing import *
import dataclasses, ipaddress, json, logging, re, time
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass
from contextlib import contextmanager
from fastapi import FastAPI, Request, Response, HTTPException
from guard import *

app = FastAPI()
config = SecurityConfig(
    ipinfo_token="test-token",
    behavior_scan_response_body=True,
    enable_redis=True,
    redis_url="redis://localhost:6379",
)
security_config = config
guard_deco = SecurityDecorator(config)
redis_handler = RedisManager(config)
sus_patterns_handler.configure(config)


async def _teardown():
    for _manager in (ip_ban_manager, security_headers_manager, cloud_handler):
        _manager.redis_handler = None
    for _manager in (ip_ban_manager, security_headers_manager, cloud_handler):
        _manager.redis_handler = None
    await ip_ban_manager.reset()
    await security_headers_manager.reset()
    await sus_patterns_handler.reset()
"""
PRELUDE_PREFIXES = ("",)


def _markdown_files() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*.md")
        if not EXCLUDED_PARTS.intersection(path.relative_to(ROOT).parts)
    )


def _python_blocks(path: Path) -> list[tuple[int, str]]:
    text = path.read_text(encoding="utf-8")
    blocks = []
    for match in FENCE.finditer(text):
        indent = match.group(1)
        body = "\n".join(
            line[len(indent) :] if line.startswith(indent) else line
            for line in match.group(2).split("\n")
        )
        blocks.append((text.count("\n", 0, match.start()) + 2, body))
    return blocks


def _prepare(body: str, label: str) -> tuple[ast.AST, CodeType]:
    # A decorator example without its function is valid documentation: close it.
    error: SyntaxError | None = None
    for source in (body, body + "\ndef _decorated(): ...\n"):
        try:
            return ast.parse(source, label), compile(
                source, label, "exec", flags=TOP_LEVEL_AWAIT
            )
        except SyntaxError as caught:
            error = caught
    assert error is not None
    raise error


def _is_guard(module_name: str) -> bool:
    return module_name.split(".")[0] in GUARD_ROOTS


def _guard_import_problems(tree: ast.AST) -> list[str]:
    problems = []
    for node in ast.walk(tree):
        names: list[tuple[str, str | None]]
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [(node.module, alias.name) for alias in node.names]
        elif isinstance(node, ast.Import):
            names = [(alias.name, None) for alias in node.names]
        else:
            continue
        for module_name, member in names:
            if not _is_guard(module_name) or PLACEHOLDER_MODULE.search(module_name):
                continue
            try:
                module = importlib.import_module(module_name)
            except ImportError as error:
                problems.append(f"line {node.lineno}: {error}")
                continue
            if member and member != "*" and not hasattr(module, member):
                try:
                    importlib.import_module(f"{module_name}.{member}")
                except ImportError:
                    problems.append(
                        f"line {node.lineno}: cannot import {member} from {module_name}"
                    )
    return problems


def _resolve(node: ast.expr, namespace: dict[str, object]) -> object | None:
    if isinstance(node, ast.Name):
        return namespace.get(node.id)
    if isinstance(node, ast.Attribute):
        owner = _resolve(node.value, namespace)
        return None if owner is None else getattr(owner, node.attr, None)
    return None


def _function_local_names(tree: ast.AST) -> set[str]:
    """Names a function or lambda in the block binds, unknown to the namespace."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            arguments = node.args
            names.update(
                a.arg
                for a in (
                    arguments.posonlyargs
                    + arguments.args
                    + arguments.kwonlyargs
                    + [x for x in (arguments.vararg, arguments.kwarg) if x]
                )
            )
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                    names.add(child.id)
    return names


def _guard_owned(obj: object) -> bool:
    module_name = getattr(obj, "__module__", None)
    if not isinstance(module_name, str):
        module_name = type(getattr(obj, "__self__", obj)).__module__
    return _is_guard(module_name)


def _call_problem(call: ast.Call, target: Callable[..., object]) -> str | None:
    if any(keyword.arg is None for keyword in call.keywords) or any(
        isinstance(arg, ast.Starred) for arg in call.args
    ):
        return None
    try:
        signature = inspect.signature(target)
    except (TypeError, ValueError):
        return None
    parameters = signature.parameters
    if not any(p.kind is p.VAR_KEYWORD for p in parameters.values()):
        unknown = [
            keyword.arg
            for keyword in call.keywords
            if keyword.arg and keyword.arg not in parameters
        ]
        if unknown:
            return f"unexpected keyword arguments {unknown}"
    try:
        signature.bind_partial(*([object()] * len(call.args)))
    except TypeError as error:
        return str(error)
    return None


def _guard_api_problems(tree: ast.AST, namespace: dict[str, object]) -> list[str]:
    problems = []
    local_names = _function_local_names(tree)
    namespace = {
        name: value for name, value in namespace.items() if name not in local_names
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target = _resolve(node.func, namespace)
            if target is not None and callable(target) and _guard_owned(target):
                problem = _call_problem(node, target)
                if problem:
                    problems.append(
                        f"line {node.lineno}: {ast.unparse(node.func)}: {problem}"
                    )
            elif (
                node.args
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"add_middleware", "add"}
            ):
                installed = _resolve(node.args[0], namespace)
                if inspect.isclass(installed) and _guard_owned(installed):
                    bare = ast.Call(func=node.func, args=[], keywords=node.keywords)
                    problem = _call_problem(bare, installed)
                    if problem:
                        problems.append(
                            f"line {node.lineno}: {installed.__name__}: {problem}"
                        )
        elif isinstance(node, ast.Attribute):
            owner = _resolve(node.value, namespace)
            if (
                owner is not None
                and not inspect.ismodule(owner)
                and _guard_owned(owner)
                and not hasattr(owner, node.attr)
            ):
                problems.append(
                    f"line {node.lineno}: {ast.unparse(node)} does not exist"
                )
    return problems


class _RejectedPatterns(logging.Handler):
    """Custom patterns guard-core refuses: add_pattern() only logs the refusal."""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        message = record.getMessage()
        if message.startswith("Rejected unsafe pattern"):
            self.messages.append(message[:160])

    def drain(self) -> list[str]:
        drained, self.messages = self.messages, []
        return drained


def _is_stub(node: ast.stmt) -> bool:
    return isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)


def _is_signature_listing(tree: ast.Module) -> bool:
    def listing(node: ast.stmt) -> bool:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            return all(_is_stub(child) for child in node.body)
        if isinstance(node, ast.ClassDef):
            return all(listing(child) or _is_stub(child) for child in node.body)
        return False

    return bool(tree.body) and all(listing(node) for node in tree.body)


@functools.cache
def _guard_callables_by_name() -> dict[str, list[object]]:
    index: dict[str, list[object]] = {}
    for root_name in GUARD_ROOTS:
        try:
            root_module = importlib.import_module(root_name)
        except ImportError:
            continue
        names = [root_name]
        names += [
            info.name
            for info in pkgutil.walk_packages(root_module.__path__, f"{root_name}.")
        ]
        for name in names:
            try:
                module = importlib.import_module(name)
            except Exception:
                continue
            for member_name, member in vars(module).items():
                if getattr(member, "__module__", None) == name and (
                    inspect.isclass(member) or inspect.isfunction(member)
                ):
                    index.setdefault(member_name, []).append(member)
                    if inspect.isclass(member):
                        for base in member.__mro__:
                            for method_name, method in vars(base).items():
                                index.setdefault(
                                    f"{member_name}.{method_name}", []
                                ).append(method)
                                index.setdefault(method_name, []).append(method)
    adapter = importlib.import_module(GUARD_ROOTS[1])
    for exported in getattr(adapter, "__all__", ()):
        member = getattr(adapter, exported, None)
        if inspect.isclass(member):
            index.setdefault(exported, []).append(member)
            for base in member.__mro__:
                for method_name, method in vars(base).items():
                    index.setdefault(f"{exported}.{method_name}", []).append(method)
    return index


def _parameters_of(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[str, bool]]:
    arguments = node.args
    positional = arguments.posonlyargs + arguments.args
    defaults = [False] * (len(positional) - len(arguments.defaults))
    defaults += [True] * len(arguments.defaults)
    found = [(a.arg, d) for a, d in zip(positional, defaults, strict=True)]
    found += [
        (a.arg, d is not None)
        for a, d in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True)
    ]
    return [
        (name, has_default)
        for name, has_default in found
        if name not in {"self", "cls"}
    ]


def _signature_matches(
    node: ast.FunctionDef | ast.AsyncFunctionDef, target: object
) -> bool:
    function = (
        target.__func__ if isinstance(target, classmethod | staticmethod) else target
    )
    if not callable(function):
        return True
    function = inspect.unwrap(function)
    try:
        signature = inspect.signature(function)
    except (TypeError, ValueError):
        return True
    real = {
        name: parameter
        for name, parameter in signature.parameters.items()
        if name not in {"self", "cls"}
    }
    if inspect.iscoroutinefunction(function) != isinstance(node, ast.AsyncFunctionDef):
        return False
    documented = _parameters_of(node)
    takes_extra = any(
        parameter.kind in {parameter.VAR_KEYWORD, parameter.VAR_POSITIONAL}
        for parameter in real.values()
    )
    if any(name not in real for name, _ in documented) and not takes_extra:
        return False
    omitted = set(real) - {name for name, _ in documented}
    return all(
        real[name].default is not real[name].empty
        or real[name].kind in {real[name].VAR_KEYWORD, real[name].VAR_POSITIONAL}
        for name in omitted
    )


def _field_default(field: FieldInfo) -> object:
    return field.get_default(call_default_factory=True)


def _model_listing_problems(tree: ast.Module) -> list[str]:
    """Pydantic models shown as `name: type = default` field lists."""
    index = _guard_callables_by_name()
    problems = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        models = [
            model
            for model in index.get(node.name, [])
            if inspect.isclass(model) and hasattr(model, "model_fields")
        ]
        if not models:
            continue
        for field in node.body:
            if not (
                isinstance(field, ast.AnnAssign) and isinstance(field.target, ast.Name)
            ):
                continue
            name = field.target.id
            if not any(name in model.model_fields for model in models):
                problems.append(
                    f"line {field.lineno}: {node.name}.{name} is not a field"
                )
                continue
            if field.value is None:
                continue
            try:
                shown = ast.literal_eval(field.value)
            except ValueError:
                continue
            defaults = [
                _field_default(model.model_fields[name])
                for model in models
                if name in model.model_fields
            ]
            if shown not in defaults and not (
                not shown and any(not default for default in defaults)
            ):
                problems.append(
                    f"line {field.lineno}: {node.name}.{name} defaults to "
                    f"{defaults[0]!r}, the page shows {shown!r}"
                )
    return problems


def _signature_listing_problems(tree: ast.Module) -> list[str]:
    if not _is_signature_listing(tree):
        return []
    index = _guard_callables_by_name()
    problems = []
    for node in tree.body:
        pairs: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []
        if isinstance(node, ast.ClassDef):
            pairs = [
                (f"{node.name}.{child.name}", child)
                for child in node.body
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
            ]
            if node.name not in index and not pairs:
                problems.append(f"line {node.lineno}: class {node.name} does not exist")
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            pairs = [(node.name, node)]
        for key, function_node in pairs:
            if function_node.name in {"_decorated", *USER_DEFINED_CONTRACTS}:
                continue
            targets = index.get(key) or index.get(function_node.name)
            if not targets:
                problems.append(
                    f"line {function_node.lineno}: {key} does not exist in the engine"
                )
            elif not any(_signature_matches(function_node, t) for t in targets):
                problems.append(
                    f"line {function_node.lineno}: {key} matches no real signature"
                )
    return problems


def _raise_timeout(_signal: int, _frame: FrameType | None) -> None:
    raise TimeoutError("a documentation block ran longer than 30 seconds")


def _refuse_network(*_args: object, **_kwargs: object) -> None:
    raise OSError("the documentation sandbox has no network")


@pytest.fixture
def sandbox(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("connect", "connect_ex", "bind"):
        monkeypatch.setattr(socket.socket, name, _refuse_network)
    monkeypatch.setattr(socket, "create_connection", _refuse_network)
    monkeypatch.setattr("time.sleep", lambda _seconds: None)
    previous = signal.signal(signal.SIGALRM, _raise_timeout)
    try:
        yield
    finally:
        signal.signal(signal.SIGALRM, previous)


async def _run_in_loop(code: CodeType, namespace: dict[str, object]) -> None:
    outcome = eval(code, namespace)
    if inspect.iscoroutine(outcome):
        await asyncio.wait_for(outcome, 30)


def _run(
    code: CodeType,
    namespace: dict[str, object],
    loop: asyncio.AbstractEventLoop | None,
) -> None:
    signal.alarm(30)
    try:
        if loop is not None:
            # An async page runs under one running loop, as an async app does:
            # guard_agent() hands back the async handler there
            loop.run_until_complete(_run_in_loop(code, namespace))
            return
        outcome = eval(code, namespace)
        if inspect.iscoroutine(outcome):
            asyncio.run(asyncio.wait_for(outcome, 30))
    finally:
        signal.alarm(0)


MARKDOWN_FILES = _markdown_files()


def test_the_shipped_markdown_is_found() -> None:
    names = {path.relative_to(ROOT).as_posix() for path in MARKDOWN_FILES}
    assert "README.md" in names
    assert any(name.startswith("docs/") for name in names)
    assert any("/.agents/skills/" in name for name in names)
    assert sum(len(_python_blocks(path)) for path in MARKDOWN_FILES) > 100


@pytest.mark.usefixtures("sandbox")
@pytest.mark.parametrize(
    "path", MARKDOWN_FILES, ids=lambda path: path.relative_to(ROOT).as_posix()
)
def test_every_python_block_parses_runs_and_matches_the_api(
    path: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    name = path.relative_to(ROOT).as_posix()
    monkeypatch.chdir(tmp_path)
    for variable, value in ENVIRONMENT.items():
        monkeypatch.setenv(variable, value)
    problems: list[str] = []
    namespace: dict[str, object] = {"__name__": "documentation_snippet"}
    blocks = _python_blocks(path)
    loop = (
        asyncio.new_event_loop()
        if any("await " in body for _, body in blocks)
        else None
    )
    rejected = _RejectedPatterns()
    logging.getLogger("guard_core").addHandler(rejected)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        # A relative import in a page fragment has no package to resolve against
        warnings.simplefilter("ignore", ImportWarning)
        prelude = PRELUDE if name.startswith(PRELUDE_PREFIXES) else ALT_PRELUDE
        exec(compile(prelude, "prelude", "exec"), namespace)
        for line, body in blocks:
            label = f"{name}:{line}"
            try:
                tree, code = _prepare(body, label)
            except SyntaxError as error:
                problems.append(f"{label}: does not parse: {error}")
                continue
            problems.extend(f"{label}: {text}" for text in _guard_import_problems(tree))
            try:
                _run(code, namespace, loop)
            except SANDBOX_ERRORS:
                pass
            except GuardRedisError:
                pass
            except AssertionError as error:
                if "overwriting an existing endpoint" not in str(error):
                    problems.append(f"{label}: AssertionError: {error}")
            except Exception as error:
                problems.append(f"{label}: {type(error).__name__}: {str(error)[:200]}")
            problems.extend(
                f"{label}: {text}" for text in _guard_api_problems(tree, namespace)
            )
            if isinstance(tree, ast.Module):
                problems.extend(
                    f"{label}: {text}"
                    for text in (
                        *_signature_listing_problems(tree),
                        *_model_listing_problems(tree),
                    )
                )
            problems.extend(f"{label}: {text}" for text in rejected.drain())
    logging.getLogger("guard_core").removeHandler(rejected)
    teardown = namespace.get("_teardown")
    if callable(teardown):
        outcome = teardown()
        if inspect.iscoroutine(outcome):
            if loop is None:
                asyncio.run(outcome)
            else:
                loop.run_until_complete(outcome)
    if loop is not None:
        loop.close()
    assert not problems, "\n".join(problems)


# Release history states the defaults of the release it describes
HISTORY_PAGES = {"CHANGELOG.md", "release-notes.md"}
EMPTY_SPELLINGS = {
    "[]",
    "()",
    "{}",
    "set()",
    "frozenset()",
    "empty",
    "tuple",
    "list",
    "set",
    "frozenset",
    "dict",
    "mappingproxy",
    "mappingproxy({})",
}
NO_VALUE_SPELLINGS = {"none", "null", "-"}
TABLE_ROW = re.compile(r"^\|(.+)\|\s*$")
BULLET_DEFAULT = re.compile(
    r"^\s*[-*]\s+(?:\*\*|`)(\w+)(?:\*\*|`)(?:(?!`\w+`)[^\n])*?"
    r"(?:\([Dd]efault:?\s+|[Dd]efault:\s*)"
    r"(`[^`]*`|\"[^\"]*\"|[\w./:-]+)"
)


def _spelling(value: object) -> str:
    if value is None:
        return "none"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str | int | float):
        text = str(value).strip("`\"' ").rstrip(".,;)").lower()
        return "empty" if text in EMPTY_SPELLINGS else text
    return "empty" if not value else "complex"


PRISTINE_DEFAULTS_PROGRAM = """
import json
from guard_core.models import SecurityConfig as ConfigModel

def plain(value):
    return sorted(value) if isinstance(value, set | frozenset) else str(value)

defaults = {
    name: field.default_factory() if field.default_factory else field.default
    for name, field in ConfigModel.model_fields.items()
}
print(json.dumps(defaults, default=plain))
"""


@functools.cache
def _pristine_defaults() -> dict[str, object]:
    # A fresh interpreter: the suite's conftest repoints the redis_url and
    # redis_prefix defaults of this process at the test Redis.
    output = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", PRISTINE_DEFAULTS_PROGRAM],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    defaults: dict[str, object] = json.loads(output.splitlines()[-1])
    return defaults


def _table_blocks(path: Path) -> Iterator[list[tuple[int, list[str]]]]:
    block: list[tuple[int, list[str]]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
        row = TABLE_ROW.match(line)
        if row:
            cells = [cell.strip() for cell in re.split(r"(?<!\\)\|", row.group(1))]
            block.append((number, cells))
        elif block:
            yield block
            block = []
    if block:
        yield block


def _documented_default_problems(path: Path) -> list[str]:
    problems: list[str] = []
    if path.name in HISTORY_PAGES:
        return problems
    for block in _table_blocks(path):
        header = [cell.lower() for cell in block[0][1]]
        if "default" not in header:
            continue
        column = header.index("default")
        rows = [
            (number, cells)
            for number, cells in block[1:]
            if column < len(cells) and not set(cells[0]) <= set("-: ")
        ]
        # A table that lists anything but SecurityConfig fields describes another model
        if rows and all(
            cells[0].strip("`* ") in ConfigModel.model_fields for _, cells in rows
        ):
            for number, cells in rows:
                _check_default(
                    path, number, cells[0].strip("`* "), cells[column], problems
                )
    for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
        bullet = BULLET_DEFAULT.match(line)
        if bullet:
            _check_default(path, number, bullet.group(1), bullet.group(2), problems)
    return problems


def _claimed_spelling(documented: str) -> str:
    claimed = re.sub(r"^Path\((.*)\)$", r"\1", documented.strip("`").strip())
    claimed = re.sub(r"\s+\(.*$", "", claimed).strip("`")
    if claimed.lower() in EMPTY_SPELLINGS:
        return "empty"
    return _spelling(claimed)


def _check_default(
    path: Path, number: int, name: str, documented: str, problems: list[str]
) -> None:
    if name not in ConfigModel.model_fields:
        return
    expected = _spelling(_pristine_defaults()[name])
    claimed = _claimed_spelling(documented)
    if (
        expected == "complex"
        or claimed in {"", "required"}
        or claimed.startswith("see")
    ):
        return
    if claimed != expected:
        where = path.relative_to(ROOT).as_posix()
        problems.append(
            f"{where}:{number}: {name} default is {expected}, page says {documented}"
        )


@pytest.mark.parametrize(
    "path", MARKDOWN_FILES, ids=lambda path: path.relative_to(ROOT).as_posix()
)
def test_every_documented_security_config_default_is_the_real_default(
    path: Path,
) -> None:
    assert not _documented_default_problems(path)


def _mute_list(page: str, field: str) -> set[str]:
    match = re.search(rf"- \*\*`{field}`\*\* - (.*)", page)
    assert match, field
    return set(re.findall(r"`([a-z_]+)`", match.group(1)))


def test_the_documented_mute_values_are_the_engine_values() -> None:
    page_path = ROOT / "docs" / "tutorial" / "configuration" / "telemetry.md"
    page = page_path.read_text(encoding="utf-8")
    assert _mute_list(page, "muted_event_types") == set(EVENT_TYPE_VALUES)
    assert _mute_list(page, "muted_metric_types") == set(METRIC_TYPE_VALUES)
    assert _mute_list(page, "muted_check_logs") == set(CHECK_NAME_VALUES)
