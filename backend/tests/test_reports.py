"""PDF report generation tests (Phase 16 / 20)."""

from pathlib import Path

from app.config import get_settings
from app.database import SessionLocal
from app.models.enums import FindingSeverity
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.scanners.base import FindingData
from app.services.finding_service import persist_findings
from app.scanners.runner import _persist_hosts
from app.scanners.base import HostData, PortData


def _seed_completed_scan(db, user_id: int = 1):
    """Seed a scan owned by the tester account (id 1 in a clean test DB)."""
    target = Target(user_id=user_id, name="lab", address="127.0.0.1", address_type="ip")
    db.add(target)
    db.flush()
    scan = Scan(user_id=user_id, target_id=target.id, status="COMPLETED", risk_score=5.0)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return user_id, scan


def test_generate_report_for_completed_scan(client, auth_headers, monkeypatch, tmp_path):
    with SessionLocal() as db:
        user, scan = _seed_completed_scan(db)
        _persist_hosts(
            db,
            scan,
            [HostData(ip_address="127.0.0.1", ports=[PortData(port=8080, state="open", service="http")])],
        )
        persist_findings(
            db,
            scan,
            [
                FindingData(
                    title="Missing Content-Security-Policy header",
                    category="security-headers",
                    severity=FindingSeverity.MEDIUM,
                    description="CSP missing.",
                    evidence="GET -> 200",
                    affected_component="http://127.0.0.1:8080",
                    remediation="Set a CSP.",
                )
            ],
        )
        scan_id = scan.id

    # Point the reports directory at a temp folder.
    monkeypatch.setattr(get_settings(), "REPORTS_DIR", str(tmp_path))

    resp = client.post(f"/api/reports/scans/{scan_id}", headers=auth_headers, json={})
    assert resp.status_code == 201, resp.text
    report = resp.json()
    assert report["filename"] == f"CyberSentinel-Report-{scan_id}.pdf"

    # Download it.
    dl = client.get(f"/api/reports/{report['id']}/download", headers=auth_headers)
    assert dl.status_code == 200
    assert dl.headers["content-type"] == "application/pdf"
    assert dl.content[:5] == b"%PDF-"
    assert len(dl.content) > 5000

    listed = client.get("/api/reports", headers=auth_headers)
    assert listed.status_code == 200
    assert len(listed.json()) == 1


def test_json_export_structure(client, auth_headers, tmp_path, monkeypatch):
    """JSON export mirrors the full report structure."""
    with SessionLocal() as db:
        user_id, scan = _seed_completed_scan(db)
        _persist_hosts(
            db,
            scan,
            [HostData(ip_address="127.0.0.1", ports=[PortData(port=8080, state="open", service="http")])],
        )
        persist_findings(
            db,
            scan,
            [
                FindingData(
                    title="Missing CSP",
                    category="security-headers",
                    severity=FindingSeverity.MEDIUM,
                    description="CSP missing.",
                    evidence="GET -> 200",
                    affected_component="http://127.0.0.1:8080",
                    remediation="Set a CSP.",
                )
            ],
        )
        scan.summary_json = '{"technologies": ["Python"]}'
        db.commit()
        scan_id = scan.id

    monkeypatch.setattr(get_settings(), "REPORTS_DIR", str(tmp_path))
    report = client.post(f"/api/reports/scans/{scan_id}", headers=auth_headers, json={}).json()

    resp = client.get(f"/api/reports/{report['id']}/export?format=json", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert f'filename="CyberSentinel-Report-{scan_id}.json"' in resp.headers["content-disposition"]

    data = resp.json()
    assert data["report"]["scan_id"] == scan_id
    assert data["target"]["address"] == "127.0.0.1"
    assert data["technologies"] == ["Python"]
    assert data["hosts"][0]["ports"][0]["port"] == 8080
    assert data["findings"][0]["title"] == "Missing CSP"
    assert data["findings"][0]["severity"] == "MEDIUM"
    assert data["severity_distribution"]["MEDIUM"] == 1


def test_csv_export_sanitizes_formula_injection(client, auth_headers, tmp_path, monkeypatch):
    """CSV export escapes cells that could execute spreadsheet formulas."""
    with SessionLocal() as db:
        user_id, scan = _seed_completed_scan(db)
        persist_findings(
            db,
            scan,
            [
                FindingData(
                    title="=HYPERLINK(\"http://evil\")",
                    category="info-disclosure",
                    severity=FindingSeverity.LOW,
                    description="banner",
                    evidence="-XSS",
                    remediation="@hidden",
                )
            ],
        )
        scan_id = scan.id

    monkeypatch.setattr(get_settings(), "REPORTS_DIR", str(tmp_path))
    report = client.post(f"/api/reports/scans/{scan_id}", headers=auth_headers, json={}).json()

    resp = client.get(f"/api/reports/{report['id']}/export?format=csv", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    text = resp.content.decode("utf-8-sig")  # BOM stripped
    lines = text.strip().split("\r\n")
    assert lines[0] == "title,category,severity,cvss_score,cvss_vector,affected_asset,affected_component,evidence,remediation,reference,status"
    assert "'=HYPERLINK" in text  # formula neutralized
    assert "'-XSS" in text  # leading dash neutralized
    assert "'@hidden" in text  # leading @ neutralized


def test_export_requires_ownership(client, auth_headers):
    """Export of another user's report is rejected (404)."""
    from app.models.report import Report

    with SessionLocal() as db:
        _, scan = _seed_completed_scan(db, user_id=2)  # another user's scan
        report = Report(
            scan_id=scan.id,
            filename="other.pdf",
            file_path="/tmp/other.pdf",
            file_format="pdf",
        )
        db.add(report)
        db.commit()
        report_id = report.id

    resp = client.get(f"/api/reports/{report_id}/export?format=json", headers=auth_headers)
    assert resp.status_code == 404


def test_export_invalid_format_rejected(client, auth_headers, tmp_path, monkeypatch):
    with SessionLocal() as db:
        user_id, scan = _seed_completed_scan(db)
        scan_id = scan.id
    monkeypatch.setattr(get_settings(), "REPORTS_DIR", str(tmp_path))
    report = client.post(f"/api/reports/scans/{scan_id}", headers=auth_headers, json={}).json()
    resp = client.get(f"/api/reports/{report['id']}/export?format=xml", headers=auth_headers)
    assert resp.status_code == 422


def test_export_missing_report_404(client, auth_headers):
    resp = client.get("/api/reports/9999/export?format=json", headers=auth_headers)
    assert resp.status_code == 404


def test_csv_export_empty_findings_header_only(client, auth_headers, tmp_path, monkeypatch):
    with SessionLocal() as db:
        user_id, scan = _seed_completed_scan(db)
        scan_id = scan.id
    monkeypatch.setattr(get_settings(), "REPORTS_DIR", str(tmp_path))
    report = client.post(f"/api/reports/scans/{scan_id}", headers=auth_headers, json={}).json()
    resp = client.get(f"/api/reports/{report['id']}/export?format=csv", headers=auth_headers)
    assert resp.status_code == 200
    text = resp.content.decode("utf-8-sig")
    assert text.strip() == "title,category,severity,cvss_score,cvss_vector,affected_asset,affected_component,evidence,remediation,reference,status"


def test_report_requires_completed_scan(client, auth_headers, created_target):
    with SessionLocal() as db:
        scan = Scan(user_id=1, target_id=created_target["id"], status="RUNNING")
        db.add(scan)
        db.commit()
        scan_id = scan.id
    resp = client.post(f"/api/reports/scans/{scan_id}", headers=auth_headers, json={})
    assert resp.status_code == 409


def test_report_filename_sanitization():
    from app.utils.validation import sanitize_filename

    assert sanitize_filename("CyberSentinel-Report-1.pdf") == "CyberSentinel-Report-1.pdf"
    assert ".." not in sanitize_filename("../../etc/passwd.pdf")
    assert "/" not in sanitize_filename("a/b/c.pdf")
