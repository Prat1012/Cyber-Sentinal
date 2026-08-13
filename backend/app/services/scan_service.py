"""Scan lifecycle service: creation, listing, retrieval, cancellation."""

import logging
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.jobs import job_manager
from app.models.enums import ScanStatus
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.schemas.scan import ScanCreate
from app.services.target_service import get_target
from app.utils.errors import ConflictError, NotFoundError, ScanAuthorizationError
from app.utils.validation import (
    is_loopback_or_private,
    resolve_hostname_to_ips,
    validate_port_range,
)

logger = logging.getLogger(__name__)

MAX_QUEUED_PER_USER = 20


def assert_scan_authorized(target: Target, settings: Settings) -> None:
    """Enforce the target safety policy (local/lab scope by default)."""
    address = target.address
    address_type = target.address_type
    allowed = settings.allowed_targets

    if address in allowed:
        return

    if address_type == "ip":
        if is_loopback_or_private(address) or settings.ALLOW_EXTERNAL_TARGETS:
            return
        raise ScanAuthorizationError(
            "Scanning public/global IP addresses is disabled by default. Set "
            "ALLOW_EXTERNAL_TARGETS=true only for explicitly authorized "
            "external assessments, or add the address to ALLOWED_TARGETS."
        )

    # Hostname targets.
    if address.lower() in ("localhost", "ip6-localhost", "localhost.localdomain"):
        return
    if settings.ALLOW_EXTERNAL_TARGETS:
        return
    ips = resolve_hostname_to_ips(address)
    if ips and all(is_loopback_or_private(ip) for ip in ips):
        return
    raise ScanAuthorizationError(
        "Target hostname does not resolve to a local/lab address. Add it to "
        "ALLOWED_TARGETS or enable ALLOW_EXTERNAL_TARGETS for authorized "
        "external assessments."
    )


def create_scan(db: Session, user: User, data: ScanCreate, settings: Settings) -> Scan:
    target = get_target(db, user, data.target_id)
    assert_scan_authorized(target, settings)
    validate_port_range(data.port_range)

    active = db.scalar(
        select(func.count(Scan.id)).where(
            Scan.user_id == user.id,
            Scan.status.in_([ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]),
        )
    ) or 0
    if active >= MAX_QUEUED_PER_USER:
        raise ConflictError(
            f"Too many active scans for this account (max {MAX_QUEUED_PER_USER})."
        )

    scan = Scan(
        user_id=user.id,
        target_id=target.id,
        status=ScanStatus.QUEUED.value,
        scan_type=data.scan_type.value,
        port_range=data.port_range,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    job_manager.submit(scan.id)
    logger.info("Queued scan %s for target %s", scan.id, target.address)
    return scan


def list_scans(db: Session, user: User, limit: int = 50, offset: int = 0) -> tuple[list[Scan], int]:
    total = db.scalar(
        select(func.count(Scan.id)).where(Scan.user_id == user.id)
    ) or 0
    rows = list(
        db.scalars(
            select(Scan)
            .where(Scan.user_id == user.id)
            .order_by(Scan.requested_at.desc())
            .limit(limit)
            .offset(offset)
        ).all()
    )
    return rows, total


def get_scan(db: Session, user: User, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.user_id != user.id:
        raise NotFoundError("Scan not found.")
    return scan


def cancel_scan(db: Session, user: User, scan_id: int) -> Scan:
    scan = get_scan(db, user, scan_id)
    if scan.status in (ScanStatus.COMPLETED.value, ScanStatus.FAILED.value, ScanStatus.CANCELLED.value):
        raise ConflictError(f"Scan is already {scan.status.lower()} and cannot be cancelled.")
    scan.status = ScanStatus.CANCELLED.value
    db.commit()
    db.refresh(scan)
    logger.info("Cancelled scan %s", scan.id)
    return scan


def delete_scan(db: Session, user: User, scan_id: int) -> None:
    scan = get_scan(db, user, scan_id)
    if scan.status in (ScanStatus.QUEUED.value, ScanStatus.RUNNING.value):
        scan.status = ScanStatus.CANCELLED.value
        db.flush()
    db.delete(scan)
    db.commit()


def scan_summary_data(db: Session, scan: Scan) -> dict:
    """Lightweight summary for list endpoints."""
    findings = list(scan.findings)
    by_severity: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
    target = db.get(Target, scan.target_id)
    return {
        "hosts_count": len(scan.hosts),
        "open_ports_count": sum(len(h.ports) for h in scan.hosts),
        "findings_count": len(findings),
        "findings_by_severity": by_severity,
        "engine": scan.scan_engine,
        "target_address": target.address if target else None,
    }
