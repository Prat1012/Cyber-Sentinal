"""Findings endpoints with filtering."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User
from app.schemas.finding import (
    FindingListResponse,
    FindingOut,
    FindingStatusUpdate,
)
from app.services import finding_service

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("", response_model=FindingListResponse)
def list_findings(
    severity: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    host: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    scan_id: Optional[int] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows, total = finding_service.list_findings(
        db,
        current_user.id,
        severity=severity,
        category=category,
        host=host,
        status=status,
        scan_id=scan_id,
        limit=limit,
        offset=offset,
    )
    items = []
    for row in rows:
        out = FindingOut.model_validate(row)
        scan = db.get(Scan, row.scan_id)
        out.target_address = scan.target.address if scan and scan.target else None
        if row.host:
            out.host_ip = row.host.ip_address
        items.append(out)
    return FindingListResponse(items=items, total=total)


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = finding_service.get_finding(db, current_user.id, finding_id)
    out = FindingOut.model_validate(finding)
    scan = db.get(Scan, finding.scan_id)
    out.target_address = scan.target.address if scan and scan.target else None
    if finding.host:
        out.host_ip = finding.host.ip_address
    return out


@router.patch("/{finding_id}/status", response_model=FindingOut)
def update_finding_status(
    finding_id: int,
    data: FindingStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = finding_service.update_finding_status(
        db, current_user.id, finding_id, data.status.value
    )
    out = FindingOut.model_validate(finding)
    scan = db.get(Scan, finding.scan_id)
    out.target_address = scan.target.address if scan and scan.target else None
    if finding.host:
        out.host_ip = finding.host.ip_address
    return out
