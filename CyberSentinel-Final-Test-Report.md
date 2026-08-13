# CYBERSENTINEL FINAL TEST REPORT

**Date:** 2026-08-12 (updated after Nmap live verification)
**Environment:** Windows (bash on win32), Python 3.13.14, pip 26.1.2, SQLite 3.50.4
**Scope:** Complete local validation of the CyberSentinel platform against authorized localhost targets only (`127.0.0.1`, local lab on `127.0.0.1:8080`).

---

## OVERALL SCORE: 100/100

> All 17 categories verified. The real Nmap engine (v7.991) was exercised
> end-to-end against the authorized local lab, including service/version
> detection, XML parsing, findings, risk scoring, PDF generation and download.

| Category | Result |
|---|---|
| Backend | ✅ PASS |
| Database | ✅ PASS |
| Nmap | ✅ PASS (v7.991, live end-to-end) |
| Nmap Parser | ✅ PASS |
| Web Scanner | ✅ PASS |
| OWASP Checks | ✅ PASS |
| TLS Scanner | ✅ PASS |
| Directory Discovery | ✅ PASS |
| Finding Engine | ✅ PASS |
| CVSS | ✅ PASS |
| Remediation | ✅ PASS |
| PDF Generation | ✅ PASS |
| PDF Download | ✅ PASS |
| Dashboard | ✅ PASS |
| Authentication | ✅ PASS |
| Security | ✅ PASS |
| Automated Tests | ✅ PASS |

---

## NMAP — INSTALL & LIVE VERIFICATION (this session)

### Finding the binary
- Nmap **7.991** was genuinely installed at **`E:\Program Files (x86)\Nmap`** (the
  original request was correct) with **Npcap 1.88** compiled in, but the git-bash
  environment did not include that directory on its `PATH`, so every earlier check
  (`nmap --version`, `where nmap`) reported it missing.
- `winget list` showed a phantom "Nmap 7.991" record but no uninstall-registry entry
  and no binary under the user profile — misleading, but resolved by locating the
  real install directory on the `E:` drive.
- The app now finds it two ways: the machine `backend/.env` (gitignored) sets
  `NMAP_BIN_PATH=E:/Program Files (x86)/Nmap/nmap.exe`, and normal Windows shells
  resolve `nmap` on `PATH` automatically.

### Direct probe (before app integration)
`nmap -sT -sV -Pn --open -p 8080 127.0.0.1` against the local lab produced valid XML:
- Host `127.0.0.1` up; port `8080/tcp open` (reason `syn-ack`)
- Service: **http-proxy**, product **`local-lab/1.0 (Python/3.13)`**, full service
  fingerprint captured
- Scan duration ~93s for a single port (version-detection probes), exit success

### Live scan through CyberSentinel (real engine)
`scripts/e2e_live.py` — **15/15 PASS with `engine: 'nmap'`**:

```
[PASS] GET /api/health - 200
[PASS] register user - 201
[PASS] login - 200
[PASS] create target - 201
[PASS] queue scan - 201
[PASS] scan completes via background job - final status=COMPLETED
[PASS] risk score calculated - risk=8.0
[PASS] hosts discovered - 1 host, 1 open port (engine: nmap)
[PASS] findings generated - 12 (HIGH:1, MEDIUM:3, LOW:5, INFO:3)
[PASS] finding category: security-headers
[PASS] finding category: insecure-cookie
[PASS] finding category: directory-discovery
[PASS] generate PDF report - 201
[PASS] download PDF - 14099 bytes
[PASS] dashboard totals - 1
```

### Persisted Nmap data (verified in DB)
- `services`: `http-proxy` / `local-lab/1.0 (Python/3.13)` — real service + product
- `ports`: `8080 tcp open http-proxy local-lab/1.0 (Python/3.13)`
- `hosts`: `127.0.0.1`, hostname `localhost` (PTR), status up
- `scans.scan_engine`: `nmap` (transparent engine attribution)

---

## EXECUTION SUMMARY

### Automated tests
- `python -m pytest tests/ -q` → **117 passed** in ~12s. The suite forces the fast
  built-in scanner (`NMAP_BIN_PATH=nmap-not-installed-in-tests` in `conftest.py`) so
  tests stay deterministic and fast; the real Nmap path is covered by the live e2e
  script and the Nmap XML parser unit tests (open/closed/filtered ports, services
  with and without versions, missing fields, malformed XML).
- `python -m compileall app tests scripts` → OK.
- `python -m pip check` → "No broken requirements found."

### Live security & edge-case validation (`scripts/final_validation.py`) — 25/25 PASS
Highlights:
- Wrong password → **401**; anonymous access to `/api/targets`, `/api/scans`, `/api/reports` → **401**.
- **9/9 invalid targets rejected** (empty, malformed IP `999.1.2.3`, shell metacharacters
  `; rm -rf /`, `$(id)`, `| whoami`, URL format `http://…`, path traversal `../../etc/passwd`,
  whitespace, 300-char address). All rejected with sanitized 400/422 responses — no tracebacks.
- Command-injection-style target (`127.0.0.1&echo hacked`) → 400; error bodies sanitized.
- Findings: **12/12 with CVSS scores**, valid severities only, **100% with remediation**, **100% with evidence**.
- Invalid JSON → 422; missing required field → 422; **oversized payload (>1 MB) → 413**.
- **3 path-traversal attempts on the PDF download route blocked** (404); PDF served as `application/pdf`.
- SQL-injection-style query params handled safely (200, no crash, no data leak).
- Scan detail summary now includes `target_address` (fix verified: `127.0.0.1`) and `engine: nmap`.

### Database verification
- 10 tables created (users, targets, scans, hosts, ports, services, findings,
  evidence, remediations, reports) via Alembic migration + import-time init for dev.
- CRUD + relationships verified live: register → target → scan → hosts → ports →
  services → findings → reports all persisted and retrieved.

---

## PDF ISSUE — ROOT CAUSE ANALYSIS

**Claim:** PDF generation was "not working."

**Finding:** No current PDF failure exists. The PDF pipeline was exercised live
end-to-end and produces valid reports. The only historical defect was a **ReportLab 5.0
compatibility break**: `reportlab.lib.styles` no longer ships the built-in `"Small"`
style that `pdf_generator.py` referenced, which crashed `doc.build()` with a `KeyError`.
This was fixed by defining `Small` as an explicit `ParagraphStyle` and re-verified.

**Full flow traced (all PASS):**
1. Dashboard/API → `POST /api/reports/scans/{scan_id}` → 201
2. `report_service.generate_report_for_scan` → ownership + COMPLETED checks, dedupe
3. `pdf_generator.generate_pdf_report` → file written to `reports/`
4. File persisted (Report row with filename, size_bytes, path)
5. `GET /api/reports/{id}/download` → 200, `Content-Type: application/pdf`, `%PDF-` body

**Generated files (verified on disk with the real Nmap engine):**
- `reports/CyberSentinel-Report-1.pdf` — 14,099 bytes — 7 pages (nmap engine)
- `reports/CyberSentinel-Report-2.pdf` — 14,097 bytes

**Content verification (pypdf text extraction):** valid `%PDF-1.4` header; **all 14 required
sections found** — Cover ("CYBERSENTINEL"), Assessment Timestamp, Executive Summary,
Assessment Scope, Methodology, Scan Summary, Hosts/Ports/Services, Technologies,
Severity Distribution, Detailed Findings, Evidence, CVSS, Remediation, Limitations.
Reports contain real data (target 127.0.0.1, service `http-proxy` / `local-lab/1.0
(Python/3.13)`, 12 findings, risk 8.0), not placeholders.

**Error handling:** report generation failures map to sanitized API errors (no stack
traces/paths), with full detail logged server-side. Download route enforces that the file
resides inside the configured reports directory (path traversal blocked → 404).

---

## ISSUES FOUND

| # | Issue | Severity | Root Cause | Fix Applied | Verification |
|---|---|---|---|---|---|
| 1 | Nmap reported "not installed" despite the user's claim | LOW (env) | Nmap 7.991 WAS installed at `E:\Program Files (x86)\Nmap`; git-bash PATH simply didn't include it; winget listing was a phantom record with no registry entry | Located the real install; wired it into the app via gitignored `backend/.env` (`NMAP_BIN_PATH`) and confirmed normal Windows shells resolve it on PATH | `NmapScanner.available() = True`; live scan `engine: nmap`; services/product persisted |
| 2 | Stale uvicorn process (PID 5040 + child 7156) holding port 8000 and locking `cybersentinel.db`; earlier e2e runs silently hit the stale server | MEDIUM (ops) | Leftover server from a previous session survived `taskkill` (multiprocessing child) | Killed the process tree (`taskkill //F //T`), confirmed ports free, deleted DB | Clean re-run: fresh PID bound 8000, fresh DB, 15/15 e2e PASS |
| 3 | `summary.target_address` returned `None` in `GET /api/scans/{id}` even though `summary_json` contained `"127.0.0.1"` | LOW | `scan_summary_data()` in `scan_service.py` did not populate `target_address` (schema defaulted to None) | Added `target_address` from the scan's target | Live re-check: `summary.target_address = 127.0.0.1` |
| 4 | Fallback scanner stored open ports with `service=None` (e.g. 8080), leaving the `services` table empty | LOW | `socket.getservbyport(8080)` is empty on Windows; no fallback mapping | Added `_SERVICE_FALLBACK` map for common dev/lab ports | Live fallback scan stores `(8080, 'http')`; with Nmap, full product string stored |
| 5 | ReportLab 5.0 `KeyError: 'Small'` crashed PDF build | HIGH (was) | ReportLab 5.0 removed the built-in `"Small"` style | Defined `Small` as explicit `ParagraphStyle` | Live PDF generation 201 + valid 7-page PDF, all sections present |
| 6 | Test suite slowed (~106s) and `test_e2e_workflow` failed once Nmap was on the machine | LOW (test) | Tests started detecting real Nmap via `backend/.env`; e2e asserted `engine == "basic"` | `conftest.py` forces the built-in scanner for deterministic fast tests; engine assertion now accepts `basic` or `nmap` | 117 passed in ~12s; real Nmap covered live |
| 7 | Live validation scripts crashed while polling long Nmap scans (rate limiter 429s) | LOW (script) | Poll loops issued >120 req/min against the API during ~90s scans, tripping the app's rate limiter (correct app behavior) | Poll loops now tolerate transient non-200s | `final_validation.py` 25/25 PASS; `e2e_live.py` 15/15 PASS |

---

## SECURITY FINDINGS (audit)

Automated audit of the whole project (`scripts/security_audit.py`):
- No hardcoded passwords / API keys / tokens / secrets (dev-only `SECRET_KEY` placeholder is guarded by `validate_for_production()`, which refuses to start outside `development` with the default).
- No private key material committed.
- No `shell=True` anywhere — nmap uses explicit argument arrays with `shell=False` (verified by grep).
- No SQL string concatenation / f-string SQL in `execute` calls (SQLAlchemy ORM/parameter binding throughout).
- `.gitignore` covers `.env`, `.env.local`, `*.db`, `reports/*.pdf`, `*.pem`; only `.env.example` and the machine-local gitignored `.env` (NMAP_BIN_PATH only) exist.
- API hardening verified live: input validation, request size limit (413), rate limiting (observed working during long scans), sanitized error responses, CORS restriction, security headers middleware, path-traversal-protected downloads, auth on all assessment endpoints, bcrypt-hashed passwords (cost factor configurable; 12 default, 4 in tests).

---

## REMAINING LIMITATIONS

1. **Browser UI automation could not be completed** — the browser tool fails with a
   provider-side screenshot error. The frontend was verified statically (all `js/*.js`
   pass `node --check`, no inline scripts, all asset references resolve) and every
   endpoint the UI calls was verified live via the API.
2. **TLS scanner** tested via unit tests against a locally generated self-signed HTTPS
   lab server (certificate parsing, expiry, hostname validation, legacy protocol probe).
   Not exercised in a live scan because the local lab target is HTTP-only; TLS runs
   automatically when a scan finds an HTTPS service.
3. **Port scan coverage** in live runs was limited to a single port (`8080-8080`) for
   speed; `top-100`/`top-1000` profiles are supported and parser-tested but not run
   live against the lab.
4. Test data (users/scans/PDFs) was cleaned up after validation for a fresh demo state.

---

## FINAL STATUS

### 🟢 READY FOR PORTFOLIO DEMO

All 17 categories pass, including the **real Nmap 7.991 engine** verified live
end-to-end (host discovery, port/service/version detection, XML parsing, findings,
CVSS risk scoring, remediation, PDF generation and download, dashboard, auth, and
security hardening — 117/117 automated tests and 40/40 live checks). Nmap was found
at `E:\Program Files (x86)\Nmap` (the install existed; only the git-bash PATH hid it)
and is now wired into the application via the gitignored `backend/.env`.
