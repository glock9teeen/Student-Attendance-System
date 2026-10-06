from __future__ import annotations

from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class SessionStartRequest(BaseModel):
    course_id: UUID
    token_ttl_seconds: int = Field(default=15, ge=1, le=900)
    geo_latitude: Optional[float] = None
    geo_longitude: Optional[float] = None
    geo_radius_meters: Optional[float] = Field(default=50.0, ge=0.0, le=50.0)


class SessionEndRequest(BaseModel):
    reason: Optional[str] = None


class AttendanceSubmitRequest(BaseModel):
    session_id: UUID
    token_id: UUID
    token_iat: int
    token_exp: int
    token_sig: str = Field(min_length=64, max_length=64)
    device_id: str = Field(min_length=1, max_length=255)
    latitude: Optional[float] = None
    longitude: Optional[float] = None
