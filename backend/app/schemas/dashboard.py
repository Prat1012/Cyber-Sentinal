"""Dashboard aggregation schemas."""

from pydantic import BaseModel


class DashboardSummary(BaseModel):
    total_scans: int = 0
    total_targets: int = 0
    open_findings: int = 0
    findings_by_severity: dict[str, int] = {}
    scans_by_status: dict[str, int] = {}
    recent_scans: list[dict] = []
    risk_distribution: dict[str, int] = {}
