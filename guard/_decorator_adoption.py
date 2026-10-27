from __future__ import annotations

from guard_core.decorators.base import BaseSecurityDecorator


def resolve_app_state_decorator(app: object) -> BaseSecurityDecorator | None:
    state = getattr(app, "state", None)
    decorator: BaseSecurityDecorator | None = getattr(state, "guard_decorator", None)
    return decorator


def adopt_app_state_decorator(
    guard_decorator: BaseSecurityDecorator | None, request: object
) -> BaseSecurityDecorator | None:
    if guard_decorator is not None or request is None:
        return guard_decorator
    scope = getattr(request, "scope", None)
    if not isinstance(scope, dict):
        return guard_decorator
    return resolve_app_state_decorator(scope.get("app"))
