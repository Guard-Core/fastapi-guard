from unittest.mock import patch

import pytest
from fastapi import FastAPI
from guard_core.handlers.cloud_handler import cloud_handler_for
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from guard import SecurityConfig, SecurityDecorator
from guard.middleware import SecurityMiddleware


@pytest.fixture
async def decorator_app(security_config: SecurityConfig) -> FastAPI:
    """Create FastAPI app with decorator integration using existing security_config."""
    app = FastAPI()

    cloud_handler_for(security_config, bind=True)
    security_config.trusted_proxies = ("127.0.0.1",)
    security_config.enable_penetration_detection = False
    security_config.whitelist = ()
    security_config.blacklist = ()

    decorator = SecurityDecorator(security_config)

    @decorator.require_ip(whitelist=["127.0.0.1", "192.168.1.0/24"])
    @app.get("/whitelist")
    async def whitelist_endpoint() -> dict[str, str]:
        return {"message": "Whitelisted IP access"}

    @decorator.require_ip(blacklist=["10.0.0.1", "172.16.0.0/16"])
    @app.get("/blacklist")
    async def blacklist_endpoint() -> dict[str, str]:
        return {"message": "Not blacklisted"}

    @decorator.block_countries(["CN", "RU"])
    @app.get("/block-countries")
    async def block_countries_endpoint() -> dict[str, str]:
        return {"message": "Country allowed"}

    @decorator.allow_countries(["US", "GB", "DE"])
    @app.get("/allow-countries")
    async def allow_countries_endpoint() -> dict[str, str]:
        return {"message": "Country whitelisted"}

    @decorator.block_clouds(["AWS", "GCP"])
    @app.get("/block-clouds")
    async def block_clouds_endpoint() -> dict[str, str]:
        return {"message": "Not from blocked cloud"}

    @decorator.block_clouds()
    @app.get("/block-all-clouds")
    async def block_all_clouds_endpoint() -> dict[str, str]:
        return {"message": "Not from any cloud"}

    @decorator.bypass(["ip", "rate_limit"])
    @app.get("/bypass")
    async def bypass_endpoint() -> dict[str, str]:
        return {"message": "Security bypassed"}

    @decorator.require_ip(whitelist=["192.168.1.100"])
    @decorator.block_countries(["FR"])
    @app.get("/multiple")
    async def multiple_decorators_endpoint() -> dict[str, str]:
        return {"message": "Multiple security rules"}

    app.add_middleware(SecurityMiddleware, config=security_config)
    app.state.guard_decorator = decorator

    return app


@pytest.mark.parametrize(
    "endpoint,ip,expected_status,description",
    [
        ("/whitelist", "127.0.0.1", 200, "Whitelisted IP should pass"),
        ("/whitelist", "192.168.1.50", 200, "IP in whitelisted CIDR should pass"),
        ("/whitelist", "10.0.0.1", 403, "Non-whitelisted IP should be blocked"),
        ("/blacklist", "127.0.0.1", 200, "Non-blacklisted IP should pass"),
        ("/blacklist", "10.0.0.1", 403, "Blacklisted IP should be blocked"),
        ("/blacklist", "172.16.5.10", 403, "IP in blacklisted CIDR should be blocked"),
    ],
)
async def test_ip_access_control(
    decorator_app: FastAPI,
    endpoint: str,
    ip: str,
    expected_status: int,
    description: str,
) -> None:
    """Test IP whitelist and blacklist decorators."""
    async with AsyncClient(
        transport=ASGITransport(app=decorator_app), base_url="http://test"
    ) as client:
        response = await client.get(
            endpoint,
            headers={"X-Forwarded-For": ip},
        )
        assert response.status_code == expected_status, description


@pytest.mark.parametrize(
    "endpoint,country,expected_status,description",
    [
        ("/block-countries", "US", 200, "Allowed country should pass"),
        ("/block-countries", "CN", 403, "Blocked country should be rejected"),
        ("/block-countries", "RU", 403, "Blocked country should be rejected"),
        ("/allow-countries", "US", 200, "Whitelisted country should pass"),
        ("/allow-countries", "GB", 200, "Whitelisted country should pass"),
        ("/allow-countries", "FR", 403, "Non-whitelisted country should be blocked"),
    ],
)
async def test_country_access_control(
    decorator_app: FastAPI,
    endpoint: str,
    country: str,
    expected_status: int,
    description: str,
) -> None:
    """Test country blocking and allowing decorators."""
    test_ips = {
        "US": "8.8.8.8",
        "CN": "1.2.3.4",
        "RU": "5.6.7.8",
        "GB": "9.9.9.9",
        "DE": "10.10.10.10",
        "FR": "11.11.11.11",
    }

    with patch(
        "guard_core.handlers.ipinfo_handler.IPInfoManager.get_country"
    ) as mock_geo:
        mock_geo.return_value = country

        async with AsyncClient(
            transport=ASGITransport(app=decorator_app), base_url="http://test"
        ) as client:
            response = await client.get(
                endpoint,
                headers={"X-Forwarded-For": test_ips[country]},
            )
            assert response.status_code == expected_status, description


async def test_cloud_provider_blocking(
    decorator_app: FastAPI, security_config: SecurityConfig
) -> None:
    """Test cloud provider blocking decorator."""
    with patch.object(cloud_handler_for(security_config), "is_cloud_ip") as mock_cloud:
        mock_cloud.return_value = False
        async with AsyncClient(
            transport=ASGITransport(app=decorator_app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/block-clouds",
                headers={"X-Forwarded-For": "192.168.1.1"},
            )
            assert response.status_code == 200

        mock_cloud.return_value = True
        async with AsyncClient(
            transport=ASGITransport(app=decorator_app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/block-clouds",
                # NOTE: AWS IP
                headers={"X-Forwarded-For": "54.240.0.1"},
            )
            assert response.status_code == 403


async def test_block_all_clouds_default(
    decorator_app: FastAPI, security_config: SecurityConfig
) -> None:
    """Test block_clouds decorator with default behavior (blocks all providers)."""
    with patch.object(cloud_handler_for(security_config), "is_cloud_ip") as mock_cloud:
        mock_cloud.return_value = False
        async with AsyncClient(
            transport=ASGITransport(app=decorator_app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/block-all-clouds",
                headers={"X-Forwarded-For": "192.168.1.1"},
            )
            assert response.status_code == 200

        mock_cloud.return_value = True
        async with AsyncClient(
            transport=ASGITransport(app=decorator_app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/block-all-clouds",
                headers={"X-Forwarded-For": "54.240.0.1"},  # AWS IP
            )
            assert response.status_code == 403


async def test_security_bypass(decorator_app: FastAPI) -> None:
    """Test security bypass decorator."""
    async with AsyncClient(
        transport=ASGITransport(app=decorator_app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/bypass",
            headers={"X-Forwarded-For": "192.168.1.1"},
        )
        assert response.status_code == 200


async def test_multiple_decorators(decorator_app: FastAPI) -> None:
    """Stacked decorators enforce every aspect independently (guard-core 3.5.0):
    an ip_whitelist match grants the IP aspect only, so a route-blocked
    country still denies the request."""
    with patch(
        "guard_core.handlers.ipinfo_handler.IPInfoManager.get_country"
    ) as mock_geo:
        mock_geo.return_value = "US"
        async with AsyncClient(
            transport=ASGITransport(app=decorator_app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/multiple",
                headers={"X-Forwarded-For": "192.168.1.100"},
            )
            assert response.status_code == 200

        mock_geo.return_value = "FR"
        async with AsyncClient(
            transport=ASGITransport(app=decorator_app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/multiple",
                headers={"X-Forwarded-For": "192.168.1.100"},
            )
            assert response.status_code == 403

        mock_geo.return_value = "FR"
        async with AsyncClient(
            transport=ASGITransport(app=decorator_app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/multiple",
                headers={"X-Forwarded-For": "10.0.0.5"},
            )
            assert response.status_code == 403
