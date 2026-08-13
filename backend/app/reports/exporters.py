"""CSV / JSON report export builders.

Exports are generated on the fly from persisted scan data (hosts, ports,
findings) so no extra files need to be stored alongside the PDF. The JSON
export mirrors the full structure of the PDF report; the CSV export is a
flat, spreadsheet-friendly findings table.

Security: CSV cells are sanitized against spreadsheet formula injection
(cells beginning with ``=``, ``+``, ``-``, ``@`` or tab/CR are prefixed with
a single quote) because finding text originates from target responses.
"""

import csv
import io
import json
from datetime import datetime
from typing import Any, Optional

from app.models.finding import Finding
from app.models.host import Host
from app.models.scan import Scan
from app.models.target import Target
from app.utils.validation import sanitize_filename

# Characters that mark the start of a spreadsheet formula when a cell is
# opened in Excel/LibreOffice (CSV injection / formula injection).
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

CSV_COLUMNS = [
    "title",
    "category",
    "severity",
    "cvss_score",
    "cvss_vector",
    "affected_asset",
    "affected_component",
    "evidence",
    "remediation",
    "reference",
    "status",
]


def _csv_safe(value: Any) -> str:
    """Return a CSV cell value that cannot trigger spreadsheet formula execution."""
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def build_json_export(
    scan: Scan,
    target: Target,
    hosts: list[Host],
    findings: list[Finding],
    technologies: Optional[list[str]] = None,
) -> dict:
    """Full structured JSON representation of a scan report."""
    severity_counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    host_rows = []
    for host in hosts:
        host_rows.append(
            {
                "ip_address": host.ip_address,
                "hostname": host.hostname,
                "status": host.status,
                "os_guess": host.os_guess,
                "ports": [
                    {
                        "port": port.port,
                        "protocol": port.protocol,
                        "state": port.state,
                        "service": port.service,
                        "product": port.product,
                        "version": port.version,
                    }
                    for port in host.ports
                ],
            }
        )

    return {
        "report": {
            "scan_id": scan.id,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
            "export_format": "json",
        },
        "scan": {
            "status": scan.status,
            "scan_type": scan.scan_type,
            "port_range": scan.port_range,
            "scan_engine": scan.scan_engine,
            "risk_score": scan.risk_score,
            "requested_at": _iso(scan.requested_at),
            "started_at": _iso(scan.started_at),
            "completed_at": _iso(scan.completed_at),
            "duration_seconds": scan.duration_seconds,
            "error_message": scan.error_message,
        },
        "target": {
            "address": target.address,
            "address_type": target.address_type,
            "name": target.name,
        },
        "technologies": technologies or [],
        "hosts": host_rows,
        "severity_distribution": severity_counts,
        "findings": [
            {
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "description": f.description,
                "evidence": f.evidence,
                "affected_asset": f.affected_asset,
                "affected_component": f.affected_component,
                "remediation": f.remediation,
                "reference": f.reference,
                "status": f.status,
            }
            for f in findings
        ],
    }


def build_csv_export(findings: list[Finding]) -> str:
    """Flat findings table as CSV (UTF-8 with BOM for spreadsheet apps)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for f in findings:
        writer.writerow(
            [
                _csv_safe(f.title),
                _csv_safe(f.category),
                _csv_safe(f.severity),
                _csv_safe(f.cvss_score),
                _csv_safe(f.cvss_vector),
                _csv_safe(f.affected_asset),
                _csv_safe(f.affected_component),
                _csv_safe(f.evidence),
                _csv_safe(f.remediation),
                _csv_safe(f.reference),
                _csv_safe(f.status),
            ]
        )
    return "\ufeff" + buffer.getvalue()


def export_filename(scan_id: int, fmt: str) -> str:
    """Sanitized download filename, e.g. CyberSentinel-Report-7.csv."""
    return sanitize_filename(f"CyberSentinel-Report-{scan_id}.{fmt}")


def scan_technologies(scan: Scan) -> list[str]:
    """Read detected technologies recorded in the scan summary JSON."""
    if not scan.summary_json:
        return []
    try:
        data = json.loads(scan.summary_json)
        return list(data.get("technologies", []))
    except (ValueError, TypeError):
        return []


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat()
