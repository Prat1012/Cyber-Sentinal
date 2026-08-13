"""Report request/response schemas."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class ReportCreate(BaseModel):
    """Optional overrides when generating a report for a scan."""

    author: Optional[str] = None


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    filename: str
    file_format: str
    size_bytes: Optional[int] = None
    created_at: datetime
