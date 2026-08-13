"""Shared data structures for scanner output.

Scanners produce plain dataclasses; persistence happens in the scan runner so
scanner modules stay pure and testable.
"""

from dataclasses import dataclass, field
from typing import Optional

from app.models.enums import FindingSeverity
from app.services.risk_service import score_for_severity


@dataclass
class PortData:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra: dict = field(default_factory=dict)


@dataclass
class HostData:
    ip_address: str
    hostname: Optional[str] = None
    status: str = "up"
    os_guess: Optional[str] = None
    mac_address: Optional[str] = None
    is_local: bool = False
    ports: list[PortData] = field(default_factory=list)


@dataclass
class FindingData:
    """Unified vulnerability finding format (Phase 9)."""

    title: str
    category: str
    severity: FindingSeverity
    description: str
    evidence: Optional[str] = None
    affected_component: Optional[str] = None
    remediation: Optional[str] = None
    reference: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None

    def __post_init__(self) -> None:
        # Consistent severity rules: if no explicit score was supplied, use the
        # documented representative score for the severity class.
        if self.cvss_score is None:
            self.cvss_score = score_for_severity(self.severity)


@dataclass
class WebResult:
    url: str
    status_code: int
    headers: dict[str, str]
    final_url: str
    redirect_chain: list[str]
    cookies: list[dict]
    technologies: list[str]
    content_length: int
    content_type: str = ""


@dataclass
class TLSResult:
    hostname: str
    port: int
    connected: bool = False
    tls_version: Optional[str] = None
    cert_valid: Optional[bool] = None
    days_to_expiry: Optional[float] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    san: Optional[str] = None
    self_signed: Optional[bool] = None
    hostname_mismatch: bool = False
    legacy_tls_supported: bool = False
    errors: list[str] = field(default_factory=list)


@dataclass
class DirEntry:
    url: str
    status_code: int
    content_length: int
    content_type: str = ""
