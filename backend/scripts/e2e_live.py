"""End-to-end validation against a LIVE CyberSentinel server.

Exercises the production path including the background scan job manager:

    python scripts/local_lab.py --port 8080
    uvicorn app.main:app --port 8000
    python scripts/e2e_live.py --base http://127.0.0.1:8000

Prints a checklist and exits non-zero on any failure.
"""

import argparse
import sys
import time

import requests

BASE = "http://127.0.0.1:8000"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default=BASE)
    args = parser.parse_args()
    base = args.base.rstrip("/")

    ok = True

    def check(label: str, condition: bool, extra: str = "") -> None:
        nonlocal ok
        status = "PASS" if condition else "FAIL"
        print(f"[{status}] {label}" + (f" - {extra}" if extra else ""))
        if not condition:
            ok = False

    s = requests.Session()

    # 1. Health
    r = s.get(f"{base}/api/health", timeout=5)
    check("GET /api/health", r.status_code == 200 and r.json() == {"status": "ok"}, str(r.status_code))

    # 2. Auth
    user = f"e2e{int(time.time())}"
    r = s.post(f"{base}/api/auth/register", json={"username": user, "password": "password123"}, timeout=5)
    check("register user", r.status_code == 201, str(r.status_code))
    r = s.post(f"{base}/api/auth/login", json={"username": user, "password": "password123"}, timeout=5)
    check("login", r.status_code == 200, str(r.status_code))
    token = r.json()["access_token"]
    s.headers["Authorization"] = f"Bearer {token}"

    # 3. Target
    r = s.post(f"{base}/api/targets", json={"name": "Local lab", "address": "127.0.0.1"}, timeout=5)
    check("create target", r.status_code == 201, str(r.status_code))
    target_id = r.json()["id"]

    # 4. Scan (background job)
    r = s.post(f"{base}/api/scans", json={"target_id": target_id, "scan_type": "full", "port_range": "8080-8080"}, timeout=5)
    check("queue scan", r.status_code == 201, str(r.status_code))
    scan_id = r.json()["id"]

    status = None
    # Nmap version detection can take ~90s even for a single port, so allow
    # up to 5 minutes for the background scan job. Poll at 1s (60 req/min)
    # to stay comfortably under the API's 120 req/min rate limit. Tolerate
    # transient 429s (rate limiter) and other blips while polling.
    for _ in range(600):
        r = s.get(f"{base}/api/scans/{scan_id}", timeout=5)
        if r.status_code == 200:
            status = r.json().get("scan", {}).get("status")
            if status in ("COMPLETED", "FAILED", "CANCELLED"):
                break
        time.sleep(1.0)
    check("scan completes via background job", status == "COMPLETED", f"final status={status}")

    detail = s.get(f"{base}/api/scans/{scan_id}", timeout=5).json()
    risk = detail["scan"]["risk_score"]
    check("risk score calculated", bool(risk) and risk > 0, f"risk={risk}")
    check("hosts discovered", detail["summary"]["hosts_count"] >= 1, str(detail["summary"]))
    check("findings generated", detail["summary"]["findings_count"] >= 5, str(detail["summary"]["findings_count"]))

    # 5. Findings
    findings = s.get(f"{base}/api/findings", timeout=5).json()["items"]
    cats = {f["category"] for f in findings}
    for required in ("security-headers", "insecure-cookie", "directory-discovery"):
        check(f"finding category: {required}", required in cats)

    # 6. PDF report
    r = s.post(f"{base}/api/reports/scans/{scan_id}", json={}, timeout=30)
    check("generate PDF report", r.status_code == 201, str(r.status_code))
    report_id = r.json()["id"]
    r = s.get(f"{base}/api/reports/{report_id}/download", timeout=15)
    check("download PDF", r.status_code == 200 and r.content[:5] == b"%PDF-" and len(r.content) > 5000, f"{len(r.content)} bytes")

    # 7. Dashboard
    dash = s.get(f"{base}/api/dashboard/summary", timeout=5).json()
    check("dashboard totals", dash["total_scans"] == 1 and dash["total_targets"] == 1, str(dash["total_scans"]))

    print()
    print("E2E LIVE WORKFLOW:", "ALL CHECKS PASSED" if ok else "FAILURES DETECTED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
