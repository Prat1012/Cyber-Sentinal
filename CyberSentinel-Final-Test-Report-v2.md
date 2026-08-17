# CYBERSENTINEL FINAL TEST REPORT — v2

**Date:** 2026-08-13
**Environment:** Windows (bash on win32), Python 3.13.14 (project `.venv`), pip 26.1.2, SQLite, Nmap 7.991
**Scope:** Startup/port debugging + full local validation against authorized localhost targets only (`127.0.0.1`, local lab on `127.0.0.1:8080`).

---

## SUMMARY — ALL CRITICAL CHECKS PASS

| Check | Result |
|---|---|
| Pytest | ✅ **PASS** — 123 passed, 0 failed, 0 skipped, 0 errors |
| Compile (`compileall app`) | ✅ **PASS** |
| `pip check` | ✅ **PASS** — "No broken requirements found." |
| Nmap binary | ✅ **PASS** — v7.991 at `E:\Program Files (x86)\Nmap\nmap.exe` |
| Real Nmap scan | ✅ **PASS** — engine recorded as **`nmap`** (not fallback/basic) |
| Database | ✅ **PASS** — hosts, ports, services, findings, reports persisted & verified |
| PDF generation | ✅ **PASS** — valid 7-page PDF, 14,104 bytes |
| PDF download | ✅ **PASS** — HTTP 200, `%PDF-1.4`, 14,104 bytes |
| API | ✅ **PASS** — health, docs, auth, targets, scans, findings, reports, dashboard |

---

## 1. PORT 8000 INVESTIGATION — ROOT CAUSE (ENVIRONMENT ISSUE)

**Classification: 🟡 ENVIRONMENT ISSUE — NOT an application bug.**

### What happened
- `uvicorn app.main:app` initialized the app perfectly ("CyberSentinel v1.0.0 started",
  "Scan job manager started", "Application startup complete") then failed to bind
  `127.0.0.1:8000` with `[Errno 10048] only one usage of each socket address is
  normally permitted`.
- `netstat -ano | grep :8000` showed **nothing** listening — the port looked free,
  which made the error look like an app bug. It was not.

### Actual culprit
A **stale CyberSentinel uvicorn instance from an earlier `--reload` attempt** was still
running (PIDs 1004 = uvicorn.exe, 7068 = python3.13.exe, both started from the
Microsoft Store **system Python**, not the project `.venv`). It held port 8000 in a
**"Bound" state without ever reaching LISTENING** — invisible to a plain `netstat`
grep, but visible via `Get-NetTCPConnection`:

```
LocalAddress LocalPort State  OwningProcess
127.0.0.1    8000      Bound  7068
```

A socket in this wedged state still blocks rebinding on Windows, producing exactly
`[Errno 10048]` even though nothing is listening.

### Resolution (per user decision)
- Identified the process as the user's **own** CyberSentinel instance (confirmed via
  command line: `uvicorn.exe app.main:app --reload`), not an unrelated application.
- **Not reused**: it was not serving traffic (Bound, not LISTENING) and ran from the
  wrong Python, so it could not serve requests.
- With explicit user approval, terminated the stale instance
  (`taskkill //PID 7068 //T //F`; the parent 1004 had already exited) and started a
  fresh CyberSentinel server on **127.0.0.1:8000** from the project `.venv`.
- **Unrelated processes were NOT touched:** port 3000 (Next.js portfolio dev server,
  PID 21632) and port 8834 (Tenable Nessus daemon, PID 22672) were identified and left
  running.

### Answer to the A/B/C question
- **A. Another CyberSentinel instance was already running** — ✅ YES (stale,
  non-serving, from the earlier failed `--reload` attempt).
- **B. Another unrelated process was using port 8000** — ❌ No.
- **C. CyberSentinel was successfully moved to another local port** — Not needed.
  After cleaning up the stale instance, CyberSentinel **runs successfully on
  port 8000** (health, docs, frontend all verified).

### Live verification on 127.0.0.1:8000
```
GET /api/health  -> {"status":"ok"}
GET /api/docs    -> 200
GET /            -> 200 (frontend mounted by the backend; no port config needed)
```

---

## 2. PYTEST ENVIRONMENT (ENVIRONMENT ISSUE)

**Classification: 🟡 ENVIRONMENT ISSUE — not an application bug.**

- `pytest` is a **declared development dependency** — present in `backend/requirements.txt`
  under the `# Testing` section (`pytest>=8.3.0`, `httpx>=0.27.0`).
- The project `.venv` was found to be **nearly empty** (only pip) — FastAPI, uvicorn,
  and all runtime deps were missing, which is also why the stale uvicorn had been
  launched from the system Python instead.
- Installed the full declared `requirements.txt` into the **project `.venv` only**
  (`backend/.venv/Scripts/python.exe -m pip install -r requirements.txt`), which
  includes pytest.
- Verified: `python -m pytest --version` → **pytest 9.1.1**.
- No global installs; no changes to production dependency declarations.

---

## 3. TEST SUITE — `pytest tests/ -q` (from `backend/`)

```
123 passed, 1 warning in 16.00s
```

- **passed: 123 | failed: 0 | skipped: 0 | errors: 0**
- The single warning is a Starlette deprecation notice about `httpx` vs `httpx2` in the
  test client — harmless, not a failure.
- Test directory confirmed as `backend/tests/` (not invented) — 16 test modules incl.
  auth, scans API, targets, findings, reports, dashboard, nmap parser, scanners
  (fallback/TLS/web), e2e workflow, validation, risk, health.

---

## 4. STATIC CHECKS

| Check | Result |
|---|---|
| `python -m compileall -q app` | ✅ PASS (no errors) |
| `python -m pip check` | ✅ PASS — "No broken requirements found." |

No genuine errors found; no fixes required.

---

## 5. NMAP VERIFICATION

- `nmap --version` → **Nmap version 7.991** (Npcap 1.88 compiled in).
- `where.exe nmap` → `E:\Program Files (x86)\Nmap\nmap.exe`.
- The app locates the real binary via the gitignored `backend/.env`
  (`NMAP_BIN_PATH=E:/Program Files (x86)/Nmap/nmap.exe`) with `shutil.which()` +
  `Path.is_file()` fallback in `NmapScanner._locate_binary`.

---

## 6. REAL LOCAL NMAP SCAN (127.0.0.1 ONLY) — THROUGH APP WORKFLOW

Ran `scripts/e2e_live.py` against the live server — **15/15 PASS**. The scan was
queued through the normal API flow, executed by the background scan job manager, and
used the **real Nmap engine**:

```
[PASS] GET /api/health - 200
[PASS] register user - 201
[PASS] login - 200
[PASS] create target - 201
[PASS] queue scan - 201
[PASS] scan completes via background job - final status=COMPLETED
[PASS] risk score calculated - risk=8.0
[PASS] hosts discovered - 1 host, 1 open port {engine: 'nmap', target_address: '127.0.0.1'}
[PASS] findings generated - 12 (INFO:3, LOW:5, MEDIUM:3, HIGH:1, CRITICAL:0)
[PASS] finding category: security-headers
[PASS] finding category: insecure-cookie
[PASS] finding category: directory-discovery
[PASS] generate PDF report - 201
[PASS] download PDF - 14104 bytes
[PASS] dashboard totals - 1
```

### Engine confirmation
- `scans.scan_engine = 'nmap'` and `summary.engines = ['nmap']` — **real Nmap engine
  confirmed, NOT fallback/basic** (the fallback path records `basic`; the engine
  attribution is transparent).
- Nmap XML was generated and parsed (`-sT -sV -Pn --open -p 8080-8080 -oX - 127.0.0.1`
  via `nmap_scanner.py` → `nmap_parser.parse_nmap_xml`).

### Persisted scan data (verified directly in `cybersentinel.db`)
- **Host:** `127.0.0.1` (hostname `localhost`, status up)
- **Port:** `8080/tcp open http-proxy` (product `local-lab/1.0 (Python/3.13)`)
- **Service:** `http-proxy` / `local-lab/1.0 (Python/3.13)`
- **Findings:** 12 stored with severity + CVSS scores (e.g. `Sensitive path exposed:
  /.git/config` HIGH 8.0; missing CSP/XFO headers MEDIUM 5.0; cookie missing
  Secure/HttpOnly/SameSite MEDIUM 5.0; version disclosure LOW 2.0)
- **Report row:** 1

### Broader profile — `top-100` scan (additional live run, this session)
Ran a second live scan against the same authorized target through the normal API
workflow with `port_range: "top-100"` (maps to `nmap --top-ports 100 -sT -sV -Pn
--open`):

- **Status:** COMPLETED in 111.9s (background job manager)
- **Engine:** `nmap` (real Nmap 7.991 — confirmed, not fallback)
- **Open ports detected: 5** — all with real service/version fingerprints:
  - `135/tcp msrpc` — `Microsoft Windows RPC`
  - `445/tcp microsoft-ds`
  - `3000/tcp` (Next.js portfolio dev server)
  - `8000/tcp http` — product `Uvicorn` (CyberSentinel itself)
  - `8080/tcp http-proxy` — product `local-lab/1.0 (Python/3.13)`
- **Findings: 19** (INFO:8, LOW:7, MEDIUM:3, HIGH:1) across 6 categories
  (`exposed-service`, `security-headers`, `directory-discovery`, `insecure-cookie`,
  `information-disclosure`, `technology-detection`)
- Web assessment modules ran against **multiple web services** (8000 + 8080),
  exercising the multi-service path; HIGH finding: `Sensitive path exposed:
  /.git/config` (CVSS 8.0)
- Risk score 8.0; summary records `engine: nmap` and technologies `[Python]`

This confirms the full multi-port pipeline: top-N port profile → service/version
detection → XML parsing → host/port/service persistence → findings + CVSS → risk
scoring → web/TLS/directory modules per open web service.

---

## 7. PDF REGRESSION TEST

**Classification: ✅ PASS — the previous PDF fix is intact and was NOT reverted.**

| Check | Result |
|---|---|
| PDF created | ✅ `reports/CyberSentinel-Report-1.pdf` on disk |
| File size > 0 | ✅ 14,104 bytes |
| Valid PDF header | ✅ `%PDF-1.4` |
| PDF opens (structure) | ✅ xref table 20 objects, `/Root` + `/Size 21`, trailer valid, ends with `%%EOF`; 7 pages |
| Findings present | ✅ 12 findings with severities (decoded from ASCII85+Flate streams) |
| Ports/services present | ✅ `8080`, `http-proxy`, product `local-lab/1.0 (Python/3.13)` |
| CVSS present | ✅ "CVSS v3.1 scale", per-finding CVSS scores + vectors |
| Remediation present | ✅ "Remediation:" per finding; `pdf_generator.py` emits remediation section |
| Download endpoint works | ✅ `GET /api/reports/1/download` → HTTP 200, `application/pdf`, 14,104 bytes, `%PDF-1.4` |

Confirmed in source: `backend/app/reports/pdf_generator.py` still defines the explicit
`Small` ParagraphStyle (the ReportLab 5.0 compatibility fix) — cover, executive
summary, scope, methodology, scan summary, hosts/ports/services, technologies,
severity distribution, detailed findings with evidence/CVSS/remediation, limitations.
The fix was **not reverted**.

---

## 8. ARCHITECTURE — UNCHANGED

- No application code was modified, rewritten, or removed.
- No duplicate scanner modules, no replaced Nmap integration, no database change,
  no UI changes.
- Only environment fixes were applied:
  1. Installed declared `requirements.txt` dependencies (incl. pytest) into the project `.venv`.
  2. Terminated the user-approved stale CyberSentinel uvicorn that was blocking port 8000.
- One throwaway verification script was created and **deleted** after use.

---

## ENVIRONMENT ISSUE vs APPLICATION BUG

| Symptom | Classification | Root cause | Fix |
|---|---|---|---|
| `[Errno 10048]` binding port 8000 | 🟡 **ENVIRONMENT** | Stale CyberSentinel uvicorn (from earlier `--reload` attempt) holding the port in a wedged "Bound" state; invisible to `netstat` | Terminated stale instance (user-approved); fresh server on 8000 |
| `No module named pytest` | 🟡 **ENVIRONMENT** | Project `.venv` was nearly empty; pytest (and all runtime deps) not installed in it | Installed declared `requirements.txt` into `.venv` only |
| Scan results / engine / PDF | 🟢 **APPLICATION — NO BUGS** | — | — |

**No application bugs were found in this session.**

---

## RUNNING STATE (left for the demo)

- CyberSentinel API + frontend: **http://127.0.0.1:8000** (docs at `/api/docs`, health at `/api/health`)
- Local lab target: **http://127.0.0.1:8080** (used as the authorized scan target)
- Unrelated processes untouched: Next.js portfolio (port 3000), Nessus (port 8834)

---

## FINAL RESULT

### 🟢 READY FOR PORTFOLIO DEMO

All critical tests pass: **123/123 automated tests**, real **Nmap 7.991** verified
end-to-end live (engine `nmap`, XML parsed, host/port/service persisted, 12 findings
with CVSS + remediation), valid **PDF generation + download**, database persistence,
and full API surface. Both startup blockers were **environment issues** (stale process
holding the port, empty virtualenv), now resolved — no application defects remain.
