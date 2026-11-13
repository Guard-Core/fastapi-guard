_CACHE_ATTRIBUTE = "guard_owns_its_routes"


def _is_guard_middleware(node: object) -> bool:
    from guard.asgi import PureASGISecurityMiddleware
    from guard.middleware import SecurityMiddleware

    return isinstance(node, (SecurityMiddleware, PureASGISecurityMiddleware))


def _registers_guard_middleware(app: object) -> bool:
    from guard.asgi import PureASGISecurityMiddleware
    from guard.middleware import SecurityMiddleware

    guards = (SecurityMiddleware, PureASGISecurityMiddleware)
    return any(
        isinstance(cls := getattr(entry, "cls", None), type) and issubclass(cls, guards)
        for entry in getattr(app, "user_middleware", None) or ()
    )


def _runs_guard_middleware(route: object) -> bool:
    # Three ways a guard middleware ends up in front of a mounted app: the mounted
    # app registered it with add_middleware (user_middleware), the Mount was given
    # it as middleware, or the app was wrapped in the pure-ASGI class before it
    # was mounted. The last two are a wrapper chain linked by `.app`.
    node = getattr(route, "app", None)
    seen: set[int] = set()
    while node is not None and id(node) not in seen:
        seen.add(id(node))
        if _is_guard_middleware(node) or _registers_guard_middleware(node):
            return True
        node = getattr(node, "app", None)
    return False


def owns_its_routes(route: object) -> bool:
    """Whether a Mount or Host serves an app with its own guard middleware, which
    enforces the routes inside it. The answer is kept on the route so the request
    path pays one attribute read; a guard middleware cannot be added to a mounted
    app once it has started."""
    owned = getattr(route, _CACHE_ATTRIBUTE, None)
    if owned is None:
        owned = _runs_guard_middleware(route)
        setattr(route, _CACHE_ATTRIBUTE, owned)
    return bool(owned)
