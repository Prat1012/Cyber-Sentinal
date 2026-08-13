"""Report service: generate PDF reports for completed scans."""

import logging
from pathlib import Path
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Target
from app.reports.pdf_generator import generate_pdf_report
from app.utils.errors import ConflictError, NotFoundError

logger = logging.getLogger(__name__)


def list_reports(db: Session, user_id: int, limit: int = 50, offset: int = 0) -> tuple[list[Report], int]:
    total = db.scalar(
        select(func.count(Report.id))
        .join(Scan, Scan.id == Report.scan_id)
        .where(Scan.user_id == user_id)
    ) or 0
    rows = list(
        db.scalars(
            select(Report)
            .join(Scan, Scan.id == Report.scan_id)
            .where(Scan.user_id == user_id)
            .order_by(Report.created_at.desc())
            .limit(limit)
            .offset(offset)
        ).all()
    )
    return rows, total


def get_report(db: Session, user_id: int, report_id: int) -> Report:
    report = db.get(Report, report_id)
    if report is None:
        raise NotFoundError("Report not found.")
    scan = db.get(Scan, report.scan_id)
    if scan is None or scan.user_id != user_id:
        raise NotFoundError("Report not found.")
    return report


def generate_report_for_scan(
    db: Session, user_id: int, scan_id: int, author: Optional[str] = None
) -> Report:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.user_id != user_id:
        raise NotFoundError("Scan not found.")
    if scan.status != "COMPLETED":
        raise ConflictError("A report can only be generated for a completed scan.")

    existing = db.scalar(
        select(Report).where(Report.scan_id == scan_id).order_by(Report.created_at.desc())
    )
    if existing:
        return existing

    target = db.get(Target, scan.target_id)
    settings = get_settings()
    hosts = list(scan.hosts)
    findings = list(scan.findings)
    output_path = generate_pdf_report(
        scan, target, hosts, findings, settings.reports_path, author=author
    )

    report = Report(
        scan_id=scan.id,
        filename=output_path.name,
        file_path=str(output_path),
        size_bytes=output_path.stat().st_size,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    logger.info("Created report %s for scan %s", report.id, scan_id)
    return report


def delete_report(db: Session, user_id: int, report_id: int) -> None:
    report = get_report(db, user_id, report_id)
    path = Path(report.file_path)
    db.delete(report)
    db.commit()
    try:
        if path.exists():
            path.unlink()
    except OSError:
        logger.warning("Could not remove report file %s", path)
