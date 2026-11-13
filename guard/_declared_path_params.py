from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass

from guard_core.adapter_support import (
    Problem,
    config_logger,
    detection_exclusion_path_param_problems,
    report_declared_path_param_problems,
    route_unknown_to_decorator_problem,
)
from guard_core.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.models import SecurityConfig
from starlette.routing import Host, Mount

from guard._owned_mounts import owns_its_routes


def _templates_and_endpoints(
    routes: Iterable[object], base: str = ""
) -> Iterator[tuple[str, object]]:
    for route in routes:
        included = getattr(route, "effective_route_contexts", None)
        if callable(included):
            for context in included():
                yield base + context.path, context.endpoint
        elif isinstance(route, (Mount, Host)) and owns_its_routes(route):
            continue
        elif isinstance(route, Mount):
            yield from _templates_and_endpoints(route.routes, base + route.path)
        elif isinstance(route, Host):
            yield from _templates_and_endpoints(route.routes, base)
        elif (endpoint := getattr(route, "endpoint", None)) is not None:
            yield base + getattr(route, "path", ""), endpoint


def _route_configs(
    routes: Iterable[object], guard_decorator: BaseSecurityDecorator
) -> Iterator[tuple[str, str | None, RouteConfig | None]]:
    for template, endpoint in _templates_and_endpoints(routes):
        route_id = getattr(endpoint, "_guard_route_id", None)
        route_config = guard_decorator.get_route_config(route_id) if route_id else None
        yield template, route_id, route_config


def declared_path_param_problems(
    app: object, guard_decorator: BaseSecurityDecorator | None
) -> list[Problem]:
    routes = getattr(app, "routes", None)
    if guard_decorator is None or routes is None:
        return []
    problems: list[Problem] = []
    unknown: dict[str, Problem] = {}
    for template, route_id, route_config in _route_configs(routes, guard_decorator):
        if route_id and route_config is None:
            unknown.setdefault(
                str(route_id), route_unknown_to_decorator_problem(str(route_id))
            )
        elif declared := getattr(route_config, "excluded_detection_path_params", None):
            problems += detection_exclusion_path_param_problems(
                str(route_id), template, declared
            )
    return problems + list(unknown.values())


def report_declared_path_params(
    config: SecurityConfig,
    app: object,
    guard_decorator: BaseSecurityDecorator | None,
    *,
    problems: list[Problem] | None = None,
    log_refusal: bool = False,
) -> None:
    """The one report point, at the lifespan warm, at the lazy first request and
    again whenever the route table changes (a route can be added after startup).
    With fail_on_misconfiguration every request raises a fresh error from the
    cached problems and the refusal is logged once per change; without it each
    problem is warned once."""
    if problems is None:
        problems = declared_path_param_problems(app, guard_decorator)
    if log_refusal and problems and config.fail_on_misconfiguration:
        config_logger.error(
            "Every request is refused until this is fixed: %s", "; ".join(problems)
        )
    report_declared_path_param_problems(
        config, problems, logger=config_logger, stacklevel=2
    )


# One entry per route list: (index of the parent entry, index of the route in it,
# id of the list, its length). The list is the app's own routes, an included
# router's, a Mount's or a Host's. The cache keeps these numbers and the problem
# strings, never a router or a list, so it cannot keep the app alive.
_Layout = tuple[tuple[int, int, int, int], ...]
_CACHE_ATTRIBUTE = "guard_declared_path_params_cache"


@dataclass(frozen=True)
class _Cache:
    layout: _Layout
    decorator_id: int
    problems: tuple[Problem, ...]


def _routes_of(route: object) -> Sequence[object] | None:
    included = getattr(route, "original_router", None)
    if included is not None:
        routes: Sequence[object] = included.routes
        return routes
    if isinstance(route, (Mount, Host)):
        return route.routes
    return None


def _identity(routes: Sequence[object]) -> int:
    # An empty list may be rebuilt on every access (a Mount of a plain ASGI app),
    # so only its length counts until it holds a route.
    return id(routes) if routes else 0


def _layout_of(root: Sequence[object]) -> _Layout:
    layout = [(-1, -1, _identity(root), len(root))]
    pending = [(0, root)]
    while pending:
        parent, routes = pending.pop()
        for index, route in enumerate(routes):
            nested = _routes_of(route)
            if nested is not None:
                layout.append((parent, index, _identity(nested), len(nested)))
                pending.append((len(layout) - 1, nested))
    return tuple(layout)


def _layout_holds(root: Sequence[object], layout: _Layout) -> bool:
    resolved: list[Sequence[object]] = []
    for parent, index, identity, length in layout:
        if parent < 0:
            routes: Sequence[object] | None = root
        else:
            try:
                child = resolved[parent][index]
            except IndexError:
                # A threadpool thread shrank the parent after its length was checked.
                return False
            routes = _routes_of(child)
        if routes is None or len(routes) != length or _identity(routes) != identity:
            return False
        resolved.append(routes)
    return True


def check_declared_path_params_on_request(
    config: SecurityConfig, app: object, guard_decorator: BaseSecurityDecorator | None
) -> None:
    """Per request, in the number of route lists and not of routes: walk the whole
    table again only when a list changed. While problems stand and the flag is on,
    every request raises a fresh error built from the cached problems."""
    root = getattr(app, "routes", None)
    state = getattr(app, "state", None)
    if guard_decorator is None or root is None or state is None:
        return
    cache: _Cache | None = getattr(state, _CACHE_ATTRIBUTE, None)
    if (
        cache is not None
        and cache.decorator_id == id(guard_decorator)
        and _layout_holds(root, cache.layout)
    ):
        if cache.problems and config.fail_on_misconfiguration:
            report_declared_path_params(
                config, app, guard_decorator, problems=list(cache.problems)
            )
        return
    cache = _Cache(
        _layout_of(root),
        id(guard_decorator),
        tuple(declared_path_param_problems(app, guard_decorator)),
    )
    setattr(state, _CACHE_ATTRIBUTE, cache)
    report_declared_path_params(
        config, app, guard_decorator, problems=list(cache.problems), log_refusal=True
    )
