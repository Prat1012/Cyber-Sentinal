"""Aggregate imports so that ``from app import models`` registers every table."""

from app.models.enums import (
    AddressType,
    FindingSeverity,
    FindingStatus,
    ScanStatus,
    ScanType,
)
from app.models.finding import Evidence, Finding, Remediation
from app.models.host import Host, Port, Service
from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User

__all__ = [
    "AddressType",
    "Evidence",
    "Finding",
    "FindingSeverity",
    "FindingStatus",
    "Host",
    "Port",
    "Remediation",
    "Report",
    "Scan",
    "ScanStatus",
    "ScanType",
    "Service",
    "Target",
    "User",
]
