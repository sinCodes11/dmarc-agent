from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(..., examples=["example.com"])
    email: EmailStr | None = None

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        value = value.strip().lower()
        if not value or "." not in value or " " in value:
            raise ValueError("domain must be a valid hostname")
        return value


class ReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    company: str = Field(..., min_length=1, max_length=120)


class ScanResponse(BaseModel):
    scan_id: str
    created_at: int
    expires_at: int
    result: dict[str, Any]


class ReportResponse(BaseModel):
    success: bool
    message: str


class ErrorResponse(BaseModel):
    error: str
    message: str
    details: dict[str, Any] | None = None
