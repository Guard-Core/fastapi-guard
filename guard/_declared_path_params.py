from collections.abc import Iterable, Iterator

from guard_core._misconfiguration import config_logger, report_misconfiguration
from guard_core._utils.route_gate import (
    path_params_missing_from_template,
    path_params_without_a_literal_segment_before,
)
from guard_core.decorators.base import BaseSecurityDecorator
from guard_core.models import SecurityConfig
from starlette.routing import Host, Mount


def _templates_and_endpoints(
    routes: Iterable[object], base: str = ""
) -> Iterator[tuple[str, object]]:
    for route in routes:
        included = getattr(route, "effective_route_contexts", None)
        if callable(included):
            for context in included():
                yield base + context.path, context.endpoint
        elif isinstance(route, Mount):
            yield from _templates_and_endpoints(route.routes, base + route.path)
        elif isinstance(route, Host):
            yield from _templates_and_endpoints(route.routes, base)
        elif (endpoint := getattr(route, "endpoint", None)) is not None:
            yield base + getattr(route, "path", ""), endpoint


def declared_path_param_problems(
    app: object, guard_decorator: BaseSecurityDecorator | None
) -> list[str]:
    routes = getattr(app, "routes", None)
    if guard_decorator is None or routes is None:
        return []
    problems: list[str] = []
    for template, endpoint in _templates_and_endpoints(routes):
        route_id = getattr(endpoint, "_guard_route_id", None)
        route_config = guard_decorator.get_route_config(route_id) if route_id else None
        declared = getattr(route_config, "excluded_detection_path_params", None)
        if not declared:
            continue
        # keep in step with SuspiciousActivityCheck._report_declared_path_param_problems
        for name in path_params_without_a_literal_segment_before(template, declared):
            problems.append(
                f"@detection_exclusion(path_params=...) on route {route_id!r} "
                f"declares {name!r}, which has no literal segment before it in the "
                f"route template {template!r}: it would exempt the whole path from "
                "the probe rows, so the whole path is scanned."
            )
        for name in path_params_missing_from_template(template, declared):
            problems.append(
                f"@detection_exclusion(path_params=...) on route {route_id!r} "
                f"declares {name!r}, which is not in the route template "
                f"{template!r}, so it exempts nothing."
            )
    return problems


def report_at_warm(
    config: SecurityConfig, app: object, guard_decorator: BaseSecurityDecorator | None
) -> None:
    for problem in declared_path_param_problems(app, guard_decorator):
        report_misconfiguration(config, problem, logger=config_logger, stacklevel=2)


def warn_at_first_request(
    app: object, guard_decorator: BaseSecurityDecorator | None
) -> None:
    for problem in declared_path_param_problems(app, guard_decorator):
        config_logger.warning(problem)
