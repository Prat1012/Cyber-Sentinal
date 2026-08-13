"""Finding request/response schemas."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import FindingStatus


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    host_id: Optional[int] = None
    host_ip: Optional[str] = None
    target_address: Optional[str] = None
    title: str
    category: str
    severity: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    description: str
    evidence: Optional[str] = None
    affected_component: Optional[str] = None
    affected_asset: Optional[str] = None
    remediation: Optional[str] = None
    reference: Optional[str] = None
    status: str
    created_at: datetime


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


class FindingListResponse(BaseModel):
    items: list[FindingOut]
    total: int
