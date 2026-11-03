import pytest
from fastapi import APIRouter, FastAPI
from guard_core._utils.route_gate import declared_path_param_spans, route_knowledge
from starlette.requests import Request
from starlette.routing import Mount, Route

from guard import SecurityConfig
from guard.adapters import StarletteGuardRequest
from guard.middleware import SecurityMiddleware

EMAIL = "jo@x.io"


def _template(app: FastAPI, path: str, root_path: str = "") -> object:
    middleware = SecurityMiddleware(
        app,
        config=SecurityConfig(
            enable_penetration_detection=False,
            enable_rate_limiting=False,
            enable_ip_banning=False,
            enable_redis=False,
        ),
    )
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "root_path": root_path,
            "headers": [],
            "query_string": b"",
            "app": app,
        }
    )
    guard_request = StarletteGuardRequest(request)
    middleware._populate_guard_state(guard_request, request)
    return getattr(guard_request.state, "guard_route_template", None)


async def _endpoint(request: Request) -> None:
    return None


def test_a_route_inside_a_parameterised_mount_carries_the_whole_template() -> None:
    inner = FastAPI()

    @inner.get("/items/{item_id:int}")
    async def item(item_id: int) -> None:
        return None

    app = FastAPI()
    app.mount("/orgs/{org}", inner)

    template = _template(app, f"/orgs/{EMAIL}/items/5")

    assert template == "/orgs/{org}/items/{item_id:int}"


def test_the_template_carries_no_value_under_a_proxy_root_path() -> None:
    inner = FastAPI()

    @inner.get("/items/{item_id:int}")
    async def item(item_id: int) -> None:
        return None

    app = FastAPI()
    app.mount("/orgs/{org}", inner)

    template = _template(app, f"/proxy/orgs/{EMAIL}/items/5", root_path="/proxy")

    assert template == "/orgs/{org}/items/{item_id:int}"
    assert isinstance(template, str)
    assert EMAIL not in template
    assert "proxy" not in template


def test_the_engine_finds_the_path_parameter_span_in_the_mounted_view_path() -> None:
    inner = FastAPI()

    @inner.get("/items/{item_id:int}")
    async def item(item_id: int) -> None:
        return None

    app = FastAPI()
    app.mount("/orgs/{org}", inner)
    view = f"/orgs/{EMAIL}/items/5"
    template = _template(app, view)
    assert isinstance(template, str)

    declared = {"org": frozenset({"recon"})}
    with route_knowledge(template, declared_path_params=declared):
        spans = declared_path_param_spans(view)

    assert spans == {"org": (6, 6 + len(EMAIL))}


def test_nested_mounts_join_every_mount_template_in_order() -> None:
    leaf = FastAPI()

    @leaf.get("/things/{thing_id}")
    async def thing(thing_id: str) -> None:
        return None

    middle = FastAPI()
    middle.mount("/teams/{team}", leaf)
    app = FastAPI()
    app.mount("/orgs/{org}", middle)

    assert _template(app, "/orgs/a/teams/b/things/c") == (
        "/orgs/{org}/teams/{team}/things/{thing_id}"
    )


def test_a_mount_over_plain_starlette_routes_joins_the_templates() -> None:
    app = FastAPI()
    app.router.routes.append(
        Mount("/orgs/{org}", routes=[Route("/items/{item_id:int}", _endpoint)])
    )

    assert _template(app, "/orgs/a/items/5") == "/orgs/{org}/items/{item_id:int}"


def test_a_route_outside_any_mount_keeps_its_own_path() -> None:
    app = FastAPI()

    @app.get("/items/{item_id:int}")
    async def item(item_id: int) -> None:
        return None

    assert _template(app, "/items/5") == "/items/{item_id:int}"


def test_include_router_prefixes_are_already_in_the_route_path() -> None:
    router = APIRouter(prefix="/api")

    @router.get("/things/{thing_id}")
    async def thing(thing_id: str) -> None:
        return None

    app = FastAPI()
    app.include_router(router, prefix="/v2")

    assert _template(app, "/v2/api/things/7") == "/v2/api/things/{thing_id}"


def test_a_mount_and_an_included_router_inside_it_join_both() -> None:
    router = APIRouter(prefix="/api")

    @router.get("/things/{thing_id}")
    async def thing(thing_id: str) -> None:
        return None

    inner = FastAPI()
    inner.include_router(router)
    app = FastAPI()
    app.mount("/orgs/{org}", inner)

    assert _template(app, "/orgs/a/api/things/7") == (
        "/orgs/{org}/api/things/{thing_id}"
    )


@pytest.mark.parametrize("path", ["/orgs/a/missing", "/nowhere"])
def test_an_unmatched_path_records_no_template(path: str) -> None:
    app = FastAPI()
    app.mount("/orgs/{org}", FastAPI())

    assert _template(app, path) is None
