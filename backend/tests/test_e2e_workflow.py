"""End-to-end local lab workflow (Phase 21).

Starts the local lab on 127.0.0.1:18080, queues a full scan, executes it
synchronously (the background job mechanism is exercised by the live server),
and verifies hosts, ports, findings, risk score, report and dashboard output.
"""

from app.config import get_settings
from app.scanners.runner import execute_scan
from tests.lab_server import HTTP_PORT, LabHTTPServer


def test_full_local_lab_workflow(client, auth_headers, created_target, monkeypatch, tmp_path):
    monkeypatch.setattr(get_settings(), "REPORTS_DIR", str(tmp_path))

    with LabHTTPServer():
        resp = client.post(
            "/api/scans",
            headers=auth_headers,
            json={
                "target_id": created_target["id"],
                "scan_type": "full",
                "port_range": f"{HTTP_PORT}-{HTTP_PORT}",
            },
        )
        assert resp.status_code == 201, resp.text
        scan_id = resp.json()["id"]

        # Run the scan synchronously (same code path as the worker thread).
        execute_scan(scan_id)

        detail = client.get(f"/api/scans/{scan_id}", headers=auth_headers).json()
        scan = detail["scan"]
        assert scan["status"] == "COMPLETED", scan.get("error_message")
        # "basic" (built-in scanner forced in conftest) or "nmap" (if the
        # suite ever runs with the real binary available).
        assert scan["scan_engine"] in ("basic", "nmap")
        assert scan["risk_score"] > 0
        assert detail["summary"]["hosts_count"] == 1
        assert detail["summary"]["open_ports_count"] == 1
        assert detail["summary"]["findings_count"] >= 5
        assert any(p["port"] == HTTP_PORT for p in detail["ports"])
        assert detail["technologies"]  # banner fingerprinting recorded technologies
        assert scan["duration_seconds"] is not None

        # Finding categories from the lab's intentional flaws.
        findings = client.get("/api/findings", headers=auth_headers).json()["items"]
        categories = {f["category"] for f in findings}
        assert "security-headers" in categories
        assert "insecure-cookie" in categories
        assert "directory-discovery" in categories
        assert "information-disclosure" in categories
        assert all(f["cvss_score"] is not None for f in findings)

        # PDF report generation.
        report = client.post(f"/api/reports/scans/{scan_id}", headers=auth_headers, json={})
        assert report.status_code == 201, report.text
        dl = client.get(f"/api/reports/{report.json()['id']}/download", headers=auth_headers)
        assert dl.content[:5] == b"%PDF-"

        # Dashboard reflects the completed assessment.
        dash = client.get("/api/dashboard/summary", headers=auth_headers).json()
        assert dash["total_scans"] == 1
        assert dash["open_findings"] == detail["summary"]["findings_count"]
        assert dash["scans_by_status"]["COMPLETED"] == 1
        assert dash["risk_distribution"]["high"] >= 0  # bucket present
