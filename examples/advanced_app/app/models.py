from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class MessageResponse(BaseModel):
    message: str
    details: dict[str, Any] | None = None


class IPInfoResponse(BaseModel):
    ip: str
    country: str | None = None
    city: str | None = None
    region: str | None = None
    is_vpn: bool | None = None
    is_cloud: bool | None = None
    cloud_provider: str | None = None


class HealthResponse(BaseModel):
    status: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReadinessResponse(BaseModel):
    status: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BasicHealthResponse(BaseModel):
    status: str


class RootResponse(BaseModel):
    message: str
    version: str
    infrastructure: dict[str, str]
    documentation: str
    routes: dict[str, str]


class StatsResponse(BaseModel):
    banned_ips: list[str]
    rate_limit_windows: dict[str, int]
    active_rules: dict[str, Any]


class ErrorResponse(BaseModel):
    detail: str
    error_code: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuthResponse(BaseModel):
    authenticated: bool
    user: str | None = None
    method: str
    permissions: list[str] = Field(default_factory=list)


class CSPViolation(BaseModel):
    violated_directive: str | None = Field(None, alias="violated-directive")
    blocked_uri: str | None = Field(None, alias="blocked-uri")
    document_uri: str | None = Field(None, alias="document-uri")
    source_file: str | None = Field(None, alias="source-file")
    line_number: int | None = Field(None, alias="line-number")

    model_config = {"populate_by_name": True}


class CSPReportRequest(BaseModel):
    csp_report: CSPViolation = Field(alias="csp-report")

    model_config = {"populate_by_name": True}


class TestPayload(BaseModel):
    input: str | None = None
    query: str | None = None
    path: str | None = None
    cmd: str | None = None
    honeypot_field: str | None = None
