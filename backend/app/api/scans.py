"""Scan management endpoints."""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.config import get_settings
from app.database import get_db
from app.models.host import Host, Port
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.schemas.scan import (
    HostOut,
    PortOut,
    ScanCreate,
    ScanDetail,
    ScanOut,
    ScanSummary,
)
from app.reports.exporters import scan_technologies
from app.services import scan_service

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def create_scan(
    data: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return scan_service.create_scan(db, current_user, data, get_settings())


@router.get("", response_model=list[ScanOut])
def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows, _ = scan_service.list_scans(db, current_user, limit=limit, offset=offset)
    return rows


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan_detail(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = scan_service.get_scan(db, current_user, scan_id)
    target = db.get(Target, scan.target_id)
    hosts = list(scan.hosts)
    ports: list[PortOut] = []
    for host in hosts:
        for p in host.ports:
            po = PortOut.model_validate(p)
            po.host_id = host.id
            po.host_ip = host.ip_address
            ports.append(po)
    summary = ScanSummary(**scan_service.scan_summary_data(db, scan))
    technologies = scan_technologies(scan)
    return ScanDetail(
        scan=ScanOut.model_validate(scan),
        target_address=target.address if target else None,
        summary=summary,
        hosts=[HostOut.model_validate(h) for h in hosts],
        ports=ports,
        technologies=technologies,
    )


@router.post("/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return scan_service.cancel_scan(db, current_user, scan_id)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    scan_service.delete_scan(db, current_user, scan_id)
