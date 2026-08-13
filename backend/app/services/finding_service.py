"""Finding engine service.

Converts raw scanner findings into persisted Finding/Evidence/Remediation
records with a unified format and consistent severity rules.
"""

import json
import logging
from typing import Optional

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.models.enums import FindingSeverity, FindingStatus
from app.models.finding import Evidence, Finding, Remediation
from app.models.host import Host
from app.models.scan import Scan
from app.models.target import Target
from app.scanners.base import FindingData
from app.utils.errors import NotFoundError

logger = logging.getLogger(__name__)

# Severity ordering for display/sorting purposes.
SEVERITY_ORDER = {
    FindingSeverity.CRITICAL.value: 0,
    FindingSeverity.HIGH.value: 1,
    FindingSeverity.MEDIUM.value: 2,
    FindingSeverity.LOW.value: 3,
    FindingSeverity.INFO.value: 4,
}


def _dedup_key(f: FindingData) -> tuple:
    return (f.title, (f.affected_component or "").lower())


def persist_findings(
    db: Session,
    scan: Scan,
    findings: list[FindingData],
    host_lookup: Optional[dict[str, int]] = None,
) -> list[Finding]:
    """Persist scanner findings, de-duplicating identical entries."""
    created: list[Finding] = []
    seen: set[tuple] = set()

    target = db.get(Target, scan.target_id)
    target_address = target.address if target else None

    for data in findings:
        key = _dedup_key(data)
        if key in seen:
            continue
        seen.add(key)

        host_id = None
        if host_lookup and data.affected_component:
            for host_ip, hid in host_lookup.items():
                if data.affected_component.startswith(host_ip):
                    host_id = hid
                    break

        finding = Finding(
            scan_id=scan.id,
            host_id=host_id,
            title=data.title,
            category=data.category,
            severity=data.severity.value,
            cvss_score=data.cvss_score,
            cvss_vector=data.cvss_vector,
            description=data.description,
            evidence=data.evidence,
            affected_component=data.affected_component,
            affected_asset=target_address,
            remediation=data.remediation,
            reference=data.reference,
            status=FindingStatus.OPEN.value,
        )
        db.add(finding)
        db.flush()

        if data.evidence:
            db.add(
                Evidence(finding_id=finding.id, detail_json=json.dumps({"note": data.evidence}))
            )
        if data.remediation:
            db.add(
                Remediation(finding_id=finding.id, action=data.remediation, steps=None)
            )
        created.append(finding)

    db.commit()
    if created:
        logger.info("Persisted %s findings for scan %s", len(created), scan.id)
    return created


def list_findings(
    db: Session,
    user_id: int,
    *,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    host: Optional[str] = None,
    status: Optional[str] = None,
    scan_id: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[Finding], int]:
    """List findings for the current user with optional filters."""
    stmt = (
        select(Finding)
        .join(Scan, Scan.id == Finding.scan_id)
        .where(Scan.user_id == user_id)
    )
    count_stmt = select(func.count(Finding.id)).join(Scan).where(Scan.user_id == user_id)

    if severity:
        stmt = stmt.where(Finding.severity == severity.upper())
        count_stmt = count_stmt.where(Finding.severity == severity.upper())
    if category:
        stmt = stmt.where(Finding.category == category)
        count_stmt = count_stmt.where(Finding.category == category)
    if status:
        stmt = stmt.where(Finding.status == status.upper())
        count_stmt = count_stmt.where(Finding.status == status.upper())
    if host:
        stmt = stmt.where(Finding.affected_component.ilike(f"%{host}%"))
        count_stmt = count_stmt.where(Finding.affected_component.ilike(f"%{host}%"))
    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
        count_stmt = count_stmt.where(Finding.scan_id == scan_id)

    total = db.scalar(count_stmt) or 0
    severity_rank = case(SEVERITY_ORDER, value=Finding.severity)
    rows = list(
        db.scalars(
            stmt.order_by(severity_rank, Finding.created_at.desc())
            .limit(limit)
            .offset(offset)
        ).all()
    )
    return rows, total


def get_finding(db: Session, user_id: int, finding_id: int) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise NotFoundError("Finding not found.")
    scan = db.get(Scan, finding.scan_id)
    if scan is None or scan.user_id != user_id:
        raise NotFoundError("Finding not found.")
    return finding


def update_finding_status(
    db: Session, user_id: int, finding_id: int, status: str
) -> Finding:
    finding = get_finding(db, user_id, finding_id)
    finding.status = status.upper()
    db.commit()
    db.refresh(finding)
    return finding


# ---------------------------------------------------------------------------
# Remediation guidance templates (used by checks that do not supply their own)
# ---------------------------------------------------------------------------
REMEDIATION_TEMPLATES: dict[str, str] = {
    "security-headers": (
        "Configure the web server to emit the missing security headers "
        "(Content-Security-Policy, Strict-Transport-Security, "
        "X-Content-Type-Options, X-Frame-Options, Referrer-Policy)."
    ),
    "insecure-cookie": (
        "Set the Secure, HttpOnly and SameSite attributes on all cookies."
    ),
    "information-disclosure": (
        "Remove or obfuscate version banners (Server / X-Powered-By headers) "
        "that reveal software and version details to unauthenticated users."
    ),
    "exposed-service": (
        "Restrict access to the exposed service with host/network firewalls, "
        "authentication, or disable the service if it is not required."
    ),
    "tls": (
        "Update the TLS certificate, correct the certificate hostname, or "
        "disable insecure TLS protocol versions and weak ciphers."
    ),
    "directory": (
        "Remove or protect sensitive paths from anonymous access; implement "
        "proper access controls instead of relying on obscurity."
    ),
}
