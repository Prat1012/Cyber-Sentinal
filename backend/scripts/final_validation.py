"""Live API validation: security edge cases, auth, target validation, summary fix.

Run against a running CyberSentinel server:
    python scripts/final_validation.py --base http://127.0.0.1:8000
"""

import argparse
import sys
import time

import requests


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8000")
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

    # --- Auth: invalid credentials must be rejected ---
    uname = f"secusr{int(time.time())}"
    r = s.post(f"{base}/api/auth/register", json={"username": uname, "password": "password123"}, timeout=5)
    check("register", r.status_code == 201, str(r.status_code))
    r = s.post(f"{base}/api/auth/login", json={"username": uname, "password": "wrongpass"}, timeout=5)
    check("login rejects wrong password", r.status_code == 401, str(r.status_code))
    r = s.post(f"{base}/api/auth/login", json={"username": uname, "password": "password123"}, timeout=5)
    check("login ok", r.status_code == 200, str(r.status_code))
    token = r.json()["access_token"]
    s.headers["Authorization"] = f"Bearer {token}"

    # --- Protected endpoints reject anonymous requests ---
    anon = requests.Session()
    r = anon.get(f"{base}/api/targets", timeout=5)
    check("anonymous blocked from /api/targets", r.status_code == 401, str(r.status_code))
    r = anon.post(f"{base}/api/scans", json={"target_id": 1}, timeout=5)
    check("anonymous blocked from /api/scans", r.status_code == 401, str(r.status_code))
    r = anon.get(f"{base}/api/reports", timeout=5)
    check("anonymous blocked from /api/reports", r.status_code == 401, str(r.status_code))

    # --- Target validation edge cases ---
    bad_targets = [
        {"name": "empty", "address": ""},
        {"name": "malformed ip", "address": "999.1.2.3"},
        {"name": "shell meta", "address": "127.0.0.1; rm -rf /"},
        {"name": "shell meta 2", "address": "$(id)"},
        {"name": "shell pipe", "address": "127.0.0.1 | whoami"},
        {"name": "url format", "address": "http://127.0.0.1"},
        {"name": "path-ish", "address": "../../etc/passwd"},
        {"name": "spaces", "address": "127.0.0.1 8080"},
        {"name": "too long", "address": "a" * 300},
    ]
    rejected = 0
    for t in bad_targets:
        r = s.post(f"{base}/api/targets", json=t, timeout=5)
        # 400 = custom ValidationFailedError handler, 422 = pydantic schema validation.
        # Either status is a safe rejection.
        if r.status_code in (400, 422):
            rejected += 1
            body = r.json().get("error", {}).get("detail", "")
            if "Traceback" in r.text or "  File " in r.text:
                check(f"no stack trace leaked for {t['name']}", False, r.text[:200])
        else:
            print(f"  NOT REJECTED ({r.status_code}): {t}")
    check("all invalid targets rejected", rejected == len(bad_targets), f"{rejected}/{len(bad_targets)}")

    # Valid local target accepted
    r = s.post(f"{base}/api/targets", json={"name": "Localhost", "address": "127.0.0.1"}, timeout=5)
    check("valid localhost target accepted", r.status_code == 201, str(r.status_code))
    target_id = r.json()["id"]

    # Command injection attempt as target must NOT appear in any engine command
    r = s.post(f"{base}/api/targets", json={"name": "inj", "address": "127.0.0.1&echo hacked"}, timeout=5)
    check("injection-style target rejected", r.status_code in (400, 422), str(r.status_code))

    # Sanitized error body: no traceback / internal paths / secrets
    r = s.post(f"{base}/api/targets", json={"name": "leak", "address": "$(id)"}, timeout=5)
    body = r.text
    leaked = any(mark in body for mark in ("Traceback", "  File ", "app\\", "app/", "secret", "SECRET"))
    check("error response is sanitized", r.status_code == 400 and not leaked, r.text[:160])

    # --- Scan + summary fix verification ---
    r = s.post(f"{base}/api/scans", json={"target_id": target_id, "scan_type": "full", "port_range": "8080-8080"}, timeout=5)
    check("queue scan", r.status_code == 201, str(r.status_code))
    scan_id = r.json()["id"]
    status = None
    # Allow up to 5 minutes for the background job (nmap -sV can be slow).
    # Poll at 1s (60 req/min) to stay under the API's 120 req/min rate limit.
    # Tolerate transient 429s (rate limiter) and other blips while polling.
    for _ in range(600):
        r = s.get(f"{base}/api/scans/{scan_id}", timeout=5)
        if r.status_code == 200:
            status = r.json().get("scan", {}).get("status")
            if status in ("COMPLETED", "FAILED", "CANCELLED"):
                break
        time.sleep(1.0)
    check("scan completed", status == "COMPLETED", f"status={status}")
    detail = s.get(f"{base}/api/scans/{scan_id}", timeout=5).json()
    check(
        "summary.target_address populated",
        detail["summary"]["target_address"] == "127.0.0.1",
        str(detail["summary"].get("target_address")),
    )
    check("summary engine present", bool(detail["summary"].get("engine")), str(detail["summary"].get("engine")))

    # --- Findings: CVSS score + severity present ---
    findings = s.get(f"{base}/api/findings", timeout=5).json()["items"]
    with_cvss = [f for f in findings if f.get("cvss_score") is not None]
    check("findings have CVSS scores", len(with_cvss) > 0, f"{len(with_cvss)}/{len(findings)}")
    sevs = {f["severity"] for f in findings}
    check("severity values valid", sevs.issubset({"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}), str(sorted(sevs)))
    # Remediation present on all findings
    no_rem = [f["title"] for f in findings if not f.get("remediation")]
    check("every finding has remediation", not no_rem, str(no_rem[:3]))
    # Evidence present
    no_ev = [f["title"] for f in findings if not f.get("evidence")]
    check("every finding has evidence", not no_ev, str(no_ev[:3]))

    # --- API security ---
    r = s.post(f"{base}/api/targets", data="not json {{{", headers={"Content-Type": "application/json"}, timeout=5)
    check("invalid JSON -> 422", r.status_code == 422, str(r.status_code))
    r = s.post(f"{base}/api/targets", json={"name": "x"}, timeout=5)
    check("missing required field -> 422", r.status_code == 422, str(r.status_code))
    # Unique address + payload larger than the 1 MB body limit -> 413
    r = s.post(f"{base}/api/targets", json={"name": "big", "address": "127.0.0.9", "notes": "x" * 1_200_000}, timeout=15)
    check("oversized payload rejected (413)", r.status_code == 413, str(r.status_code))

    # --- Report generation + path traversal on download ---
    r = s.post(f"{base}/api/reports/scans/{scan_id}", json={}, timeout=30)
    check("generate PDF", r.status_code == 201, str(r.status_code))
    report_id = r.json()["id"]
    r = s.get(f"{base}/api/reports/{report_id}/download", timeout=15)
    check(
        "download valid PDF",
        r.status_code == 200 and r.content[:5] == b"%PDF-" and len(r.content) > 5000,
        f"{len(r.content)} bytes",
    )
    check("content-type is application/pdf", r.headers.get("content-type", "").startswith("application/pdf"), r.headers.get("content-type", ""))

    # Path traversal attempts on the download route
    for bad in ("../../backend/cybersentinel.db", "%2e%2e%2fcybersentinel.db", "..%2f..%2fcybersentinel.db"):
        r = s.get(f"{base}/api/reports/{bad}/download", timeout=5)
        if r.status_code in (404, 422):
            check(f"traversal blocked: {bad[:25]}", True, str(r.status_code))
        else:
            check(f"traversal blocked: {bad[:25]}", False, f"UNEXPECTED {r.status_code}")

    # SQL injection attempt in a query param (must be treated as data, no crash)
    r = s.get(f'{base}/api/findings?severity=HIGH" OR "1"="1', timeout=5)
    check("sql-ish param handled safely", r.status_code in (200, 422), str(r.status_code))

    print()
    print("FINAL VALIDATION:", "ALL CHECKS PASSED" if ok else "FAILURES DETECTED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
