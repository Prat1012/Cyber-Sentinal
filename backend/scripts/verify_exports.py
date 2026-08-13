"""Live verification of report CSV/JSON export endpoints.

Run against a running CyberSentinel server:
    python scripts/verify_exports.py --base http://127.0.0.1:8000
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
    user = f"exp{int(time.time())}"
    r = s.post(f"{base}/api/auth/register", json={"username": user, "password": "password123"}, timeout=5)
    check("register", r.status_code == 201, str(r.status_code))
    r = s.post(f"{base}/api/auth/login", json={"username": user, "password": "password123"}, timeout=5)
    token = r.json()["access_token"]
    s.headers["Authorization"] = f"Bearer {token}"

    t = s.post(f"{base}/api/targets", json={"name": "export lab", "address": "127.0.0.1"}, timeout=5)
    target_id = t.json()["id"]
    sc = s.post(
        f"{base}/api/scans",
        json={"target_id": target_id, "scan_type": "full", "port_range": "8080-8080"},
        timeout=5,
    )
    check("queue scan", sc.status_code == 201, str(sc.status_code))
    scan_id = sc.json()["id"]

    status = None
    for _ in range(600):
        r = s.get(f"{base}/api/scans/{scan_id}", timeout=5)
        if r.status_code == 200:
            status = r.json().get("scan", {}).get("status")
            if status in ("COMPLETED", "FAILED", "CANCELLED"):
                break
        time.sleep(1.0)
    check("scan completed", status == "COMPLETED", f"status={status}")

    # Generate the PDF report (required before export exists).
    r = s.post(f"{base}/api/reports/scans/{scan_id}", json={}, timeout=30)
    check("generate PDF report", r.status_code == 201, str(r.status_code))
    report_id = r.json()["id"]

    # --- JSON export ---
    r = s.get(f"{base}/api/reports/{report_id}/export?format=json", timeout=10)
    check("export json status", r.status_code == 200, str(r.status_code))
    check("export json content-type", r.headers.get("content-type", "").startswith("application/json"), r.headers.get("content-type", ""))
    cd = r.headers.get("content-disposition", "")
    check("json filename header", f'filename="CyberSentinel-Report-{scan_id}.json"' in cd, cd)
    data = r.json()
    check("json has scan metadata", data["report"]["scan_id"] == scan_id and data["scan"]["risk_score"] is not None)
    check("json has findings", len(data["findings"]) >= 5, str(len(data["findings"])))
    check("json has hosts/ports", data["hosts"][0]["ports"][0]["port"] == 8080)
    check("json has technologies", isinstance(data["technologies"], list))
    check("json severity distribution", data["severity_distribution"]["HIGH"] >= 1, str(data["severity_distribution"]))

    # --- CSV export ---
    r = s.get(f"{base}/api/reports/{report_id}/export?format=csv", timeout=10)
    check("export csv status", r.status_code == 200, str(r.status_code))
    check("export csv content-type", r.headers.get("content-type", "").startswith("text/csv"), r.headers.get("content-type", ""))
    check("csv filename header", f'filename="CyberSentinel-Report-{scan_id}.csv"' in r.headers.get("content-disposition", ""))
    text = r.content.decode("utf-8-sig")
    header = text.split("\r\n")[0]
    check("csv header row", header == "title,category,severity,cvss_score,cvss_vector,affected_asset,affected_component,evidence,remediation,reference,status", header[:60])
    check("csv has data rows", len(text.strip().split("\r\n")) >= 2)

    # --- Invalid format rejected ---
    r = s.get(f"{base}/api/reports/{report_id}/export?format=html", timeout=5)
    check("invalid format -> 422", r.status_code == 422, str(r.status_code))

    print()
    print("EXPORT VERIFICATION:", "ALL CHECKS PASSED" if ok else "FAILURES DETECTED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
