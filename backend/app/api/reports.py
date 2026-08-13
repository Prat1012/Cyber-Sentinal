"""Report endpoints: list, generate, download, export, delete."""

import json
from pathlib import Path
from typing import Literal, Optional

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.config import get_settings
from app.database import get_db
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.reports import exporters
from app.schemas.report import ReportCreate, ReportOut
from app.services import report_service
from app.utils.errors import NotFoundError

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("", response_model=list[ReportOut])
def list_reports(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows, _ = report_service.list_reports(db, current_user.id, limit=limit, offset=offset)
    return rows


@router.post("/scans/{scan_id}", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
def generate_report(
    scan_id: int,
    data: Optional[ReportCreate] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    author = data.author if data else None
    return report_service.generate_report_for_scan(db, current_user.id, scan_id, author=author)


@router.get("/{report_id}/export")
def export_report(
    report_id: int,
    format: Literal["json", "csv"] = Query("json"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Export a report's data as JSON or CSV (generated on the fly)."""
    report = report_service.get_report(db, current_user.id, report_id)
    scan = db.get(Scan, report.scan_id)
    if scan is None:
        raise NotFoundError("Scan not found.")
    target = db.get(Target, scan.target_id)
    if target is None:
        # Target deleted after the scan ran (SQLite does not enforce FKs by
        # default) - treat as a missing report rather than a 500.
        raise NotFoundError("Report data not found.")
    hosts = list(scan.hosts)
    findings = list(scan.findings)
    technologies = exporters.scan_technologies(scan)

    filename = exporters.export_filename(scan.id, format)
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}

    if format == "json":
        payload = exporters.build_json_export(
            scan, target, hosts, findings, technologies=technologies
        )
        return Response(
            content=json.dumps(payload, indent=2, default=str),
            media_type="application/json",
            headers=headers,
        )
    return Response(
        content=exporters.build_csv_export(findings),
        media_type="text/csv; charset=utf-8",
        headers=headers,
    )


@router.get("/{report_id}/download")
def download_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    report = report_service.get_report(db, current_user.id, report_id)
    path = Path(report.file_path).resolve()
    reports_dir = get_settings().reports_path.resolve()

    # Path validation: the file must live inside the reports directory.
    try:
        path.relative_to(reports_dir)
    except ValueError:
        raise NotFoundError("Report file not found.") from None
    if not path.is_file():
        raise NotFoundError("Report file not found.")

    return FileResponse(
        path,
        media_type="application/pdf",
        filename=report.filename,
    )


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    report_service.delete_report(db, current_user.id, report_id)
