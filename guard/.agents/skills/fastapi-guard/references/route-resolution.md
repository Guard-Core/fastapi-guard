# Route Resolution and Global Behavior Rules

## Decorator visibility and pipeline size

guard-core 3.10.0 builds the security pipeline from the effective `SecurityConfig` plus the registered per-route decorator configuration, and skips any check that configuration can never trigger. Six checks are driven purely by per-route decorators, with no global-config fallback: authentication, referrer, required headers, request size/content type, custom validators, and time window. guard-core can only skip one of these when it can enumerate the registered route configuration through the middleware's `guard_decorator` attribute.

`SecurityMiddleware` now adopts `app.state.guard_decorator` itself, before the pipeline is built, so an app that wires its decorator handler that way (`app.state.guard_decorator = guard_deco`) gets the smaller pipeline instead of the conservative full one. Apps that call `middleware.set_decorator_handler(guard_deco)` directly were already covered. `guard_lifespan`, `make_lifespan`, and `guard_startup` all resolve the decorator handler the same way before calling `initialize()`, so eager boot-time initialization gets the optimization too, not just the lazy first-request path.

When no decorator handler can be found anywhere, route configuration is treated as unknown and every one of the six checks stays in the pipeline. This path can only lose the optimization, never the protection: an app that never wires a decorator handler keeps running the full set of route-driven checks, it just cannot shrink the pipeline for routes with nothing for them to check. The pipeline's startup log line names the checks that ran and appends how many were skipped.

Two `SecurityMiddleware` instances that share one `SecurityConfig` object share this pipeline only when they also resolve to the same decorator handler; see the shared-state paragraph in `SKILL.md`'s Setup section.

## route_resolution_strict

`route_resolution_strict` (`bool`, default `False`) controls what happens when the middleware cannot resolve the request to a FastAPI route.

`False` (default): the pipeline runs with no per-route config. Undecorated routes and unrouted paths pass through. This is correct when routes without decorators carry no per-route checks.

`True`: the request is blocked when the route cannot be resolved. Use this when every request must be attributable to a known route so a resolution failure cannot silently skip per-route checks.

A path that differs from a route's path only by a trailing slash resolves to that route when the app's router has `redirect_slashes` (the FastAPI default), since Starlette answers it with a 307 to that route. It gets the route's decorator config in both modes.

```python
from guard import SecurityConfig

config = SecurityConfig(route_resolution_strict=True)
```

Trade-off: with `True`, requests to paths the app does not serve turn into 500s instead of 404s. Only enable it when you want unresolved routes treated as failures.

## global_behavior_rules

`global_behavior_rules` (`list[BehaviorRuleConfig]`, default `[]`) applies behavior rules to every route, in addition to any decorator-specified rules. Useful for global 404 watchers and request-volume thresholds.

```python
from guard import SecurityConfig

config = SecurityConfig(
    global_behavior_rules=[
        {
            "rule_type": "return_pattern",
            "threshold": 20,
            "pattern": "status:404",
            "window": 300,
            "action": "log",
        },
    ],
)
```

Each rule is a mapping (or a `BehaviorRuleConfig`) with these fields:

* `rule_type`: `usage`, `return_pattern` or `frequency`.
* `threshold`: how many hits inside `window` seconds fire the rule.
* `window`: seconds the hits are counted over (default `3600`).
* `pattern`: what a `return_pattern` rule matches (`status:404`, `json:...`, `regex:...`).
* `action`: what to do when the rule fires (`ban`, `log`, `throttle` or `alert`).

Rules from decorators are merged with `global_behavior_rules` at request time; global rules do not override decorator rules, they run alongside them.

## Passive mode interaction

With `passive_mode=True`, any rule whose `action` would block instead only logs. This lets you trial `global_behavior_rules` and `route_resolution_strict=True` against production traffic without dropping legitimate requests.
