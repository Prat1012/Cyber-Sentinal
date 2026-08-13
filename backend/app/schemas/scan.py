"""Scan request/response schemas."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import ScanType
from app.utils.errors import ValidationFailedError
from app.utils.validation import validate_port_range


class ScanCreate(BaseModel):
    target_id: int
    scan_type: ScanType = ScanType.FULL
    port_range: str = Field(default="top-1000", max_length=32)

    @field_validator("port_range")
    @classmethod
    def _validate_port_range(cls, value: str) -> str:
        try:
            return validate_port_range(value)
        except ValidationFailedError as exc:
            # Raise a ValueError so pydantic reports it as a 422 validation error.
            raise ValueError(exc.detail) from exc


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    status: str
    scan_type: str
    port_range: str
    scan_engine: Optional[str] = None
    risk_score: Optional[float] = None
    error_message: Optional[str] = None
    requested_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None


class ScanSummary(BaseModel):
    hosts_count: int = 0
    open_ports_count: int = 0
    findings_count: int = 0
    findings_by_severity: dict[str, int] = {}
    engine: Optional[str] = None
    target_address: Optional[str] = None


class HostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str
    hostname: Optional[str] = None
    status: str
    os_guess: Optional[str] = None
    mac_address: Optional[str] = None


class PortOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    host_id: Optional[int] = None
    host_ip: Optional[str] = None
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


class ScanDetail(BaseModel):
    scan: ScanOut
    target_address: Optional[str] = None
    summary: Optional[ScanSummary] = None
    hosts: list[HostOut] = []
    ports: list[PortOut] = []
    technologies: list[str] = []
