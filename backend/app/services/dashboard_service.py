"""Dashboard aggregation service."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.enums import FindingSeverity, FindingStatus, ScanStatus
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.schemas.dashboard import DashboardSummary


def build_dashboard(db: Session, user_id: int) -> DashboardSummary:
    total_scans = db.scalar(
        select(func.count(Scan.id)).where(Scan.user_id == user_id)
    ) or 0
    total_targets = db.scalar(
        select(func.count(Target.id)).where(Target.user_id == user_id)
    ) or 0

    open_findings = db.scalar(
        select(func.count(Finding.id))
        .join(Scan, Scan.id == Finding.scan_id)
        .where(Scan.user_id == user_id, Finding.status == FindingStatus.OPEN.value)
    ) or 0

    # Findings by severity (OPEN only).
    severity_rows = (
        db.execute(
            select(Finding.severity, func.count(Finding.id))
            .join(Scan, Scan.id == Finding.scan_id)
            .where(
                Scan.user_id == user_id,
                Finding.status == FindingStatus.OPEN.value,
            )
            .group_by(Finding.severity)
        ).all()
    )
    findings_by_severity = {s.value: 0 for s in FindingSeverity}
    for severity, count in severity_rows:
        findings_by_severity[severity] = count

    # Scans by status.
    status_rows = (
        db.execute(
            select(Scan.status, func.count(Scan.id))
            .where(Scan.user_id == user_id)
            .group_by(Scan.status)
        ).all()
    )
    scans_by_status = {s.value: 0 for s in ScanStatus}
    for status, count in status_rows:
        scans_by_status[status] = count

    # Risk distribution: scans bucketed by their risk score.
    risk_scores = list(
        db.scalars(
            select(Scan.risk_score).where(
                Scan.user_id == user_id, Scan.risk_score.isnot(None)
            )
        ).all()
    )
    risk_distribution = {
        "none": sum(1 for s in risk_scores if s == 0),
        "low": sum(1 for s in risk_scores if 0 < s < 4),
        "medium": sum(1 for s in risk_scores if 4 <= s < 7),
        "high": sum(1 for s in risk_scores if 7 <= s < 9),
        "critical": sum(1 for s in risk_scores if s >= 9),
    }

    recent_rows = list(
        db.scalars(
            select(Scan)
            .where(Scan.user_id == user_id)
            .order_by(Scan.requested_at.desc())
            .limit(8)
        ).all()
    )
    recent_scans: list[dict] = []
    for scan in recent_rows:
        target = db.get(Target, scan.target_id)
        recent_scans.append(
            {
                "id": scan.id,
                "target_address": target.address if target else None,
                "target_name": target.name if target else None,
                "status": scan.status,
                "scan_type": scan.scan_type,
                "risk_score": scan.risk_score,
                "requested_at": scan.requested_at.isoformat() if scan.requested_at else None,
                "duration_seconds": scan.duration_seconds,
            }
        )

    return DashboardSummary(
        total_scans=total_scans,
        total_targets=total_targets,
        open_findings=open_findings,
        findings_by_severity=findings_by_severity,
        scans_by_status=scans_by_status,
        recent_scans=recent_scans,
        risk_distribution=risk_distribution,
    )
