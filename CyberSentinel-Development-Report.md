# CyberSentinel — Development Report

**Automated Vulnerability Assessment & Security Reporting Platform**

| | |
|---|---|
| Project | CyberSentinel v1.0.0 |
| Date | August 12, 2026 |
| Environment verified | Windows, Python 3.13.14, SQLite 3.50.4 |
| Test status | **117/117 pytest tests passing**, live end-to-end workflow passing |

---

## 1. Architecture

Cleanly separated backend (FastAPI) and frontend (static HTML/CSS/JS served by
the same process), with a modular `app/` layout:

- `api/` — routers (auth, targets, scans, findings, reports, dashboard)
- `services/` — business logic (auth, targets, scans, findings, CVSS risk,
  dashboard, reports)
- `scanners/` — assessment engines (nmap, nmap XML parser, web, TLS,
  directory discovery, OWASP-aligned checks, scan runner)
- `security/` — rate limiting, security headers, request size limits
- `reports/` — ReportLab PDF generator
- `models/` + `schemas/` — SQLAlchemy ORM and Pydantic DTOs
- `utils/` — redacted logging, error envelopes, input validation, crypto helpers
- `jobs.py` — background scan job queue (worker thread + semaphore)

The scanner modules produce plain dataclasses (`HostData`, `PortData`,
`FindingData`); persistence happens in the scan runner, keeping scanners pure
and unit-testable.

## 2. Implemented Features (all verified)

- **Auth** — bcrypt hashing (cost 12, configurable), JWT access tokens,
  register/login/me, per-user data isolation enforced in every service query.
- **Target management** — strict IP/hostname validation rejecting shell
  metacharacters, whitespace, malformed IPs and oversized input; duplicate and
  ownership handling.
- **Safety policy** — public/global IP scans rejected by default
  (`ALLOW_EXTERNAL_TARGETS=false`); optional `ALLOWED_TARGETS` allowlist;
  hostname targets must resolve to local/private addresses unless enabled.
- **Port discovery** — nmap via `subprocess.Popen` with argument arrays,
  `shell=False`, hard timeout, process-group termination, 20 MB XML cap, XML
  parsed into structured hosts/ports/services. Falls back to a built-in
  rate-limited TCP connect scanner when nmap is absent; the engine used is
  recorded (`nmap` / `basic`).
- **Web assessment** — security headers (CSP, HSTS, X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy), weak-CSP detection, cookie
  Secure/HttpOnly/SameSite, banner + X-Powered-By disclosure, technology
  fingerprinting; strict timeouts and a 2 MB response cap.
- **TLS analysis** — certificate validity, expiry (with <30-day warning),
  hostname match, self-signed detection, metadata (issuer/subject/SAN), best-
  effort TLS 1.0/1.1 probe.
- **Directory discovery** — configurable wordlist, per-request delay, max-path
  bound, no recursion; findings graded by sensitivity (e.g. `.git/config` HIGH).
- **Finding engine** — unified format (title, category, severity, CVSS score &
  vector, description, evidence, affected asset/component, remediation,
  reference); deduplication; Evidence and Remediation records; status workflow
  (OPEN → ACKNOWLEDGED/REMEDIATED/FALSE_POSITIVE); filtering.
- **Risk scoring** — CVSS **v3.1** base scores computed from explicit metric
  assumptions (see `app/services/risk_service.py`); severity mapping per the
  CVSS 3.1 qualitative scale; representative scores for non-exploitable checks;
  scan risk = highest finding score. Verified against known vectors (e.g.
  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8).
- **Scan management** — QUEUED/RUNNING/COMPLETED/FAILED/CANCELLED states,
  background queue with `SCAN_MAX_CONCURRENT` semaphore, in-flight
  cancellation, per-account queue cap, duration tracking.
- **PDF reports** — `CyberSentinel-Report-{scan_id}.pdf` with cover, executive
  summary, scope, methodology, scan summary, hosts/ports/services, severity
  distribution, detailed findings with evidence/CVSS/remediation, limitations
  and timestamp.
- **Dashboard** — totals, severity/risk charts (Chart.js), scan status counts,
  recent scans; dark SOC theme; live polling for running scans.
- **Hardening** — security headers on every response, restrictive CSP for the
  frontend, CORS restrictions, per-IP rate limiting (stricter on auth), 1 MB
  body limit, sanitized 500s (no stack traces), secret-redacting logs, PDF
  filename sanitization, path-traversal-safe downloads, XSS-safe frontend
  (escape helpers, no inline scripts).

## 3. Database Design

Ten tables (Alembic-managed, SQLite/PostgreSQL compatible):

```
users ──┬── targets ──┬── scans ──┬── hosts ──┬── ports ── service (1:1)
        │             │           │           └ (service detail)
        │             │           ├── findings ─┬── evidence
        │             │           │             └── remediations
        │             └───────────└── reports
        └── (ownership via user_id FK on targets and scans)
```

- All child tables cascade-delete with their parent scan/target.
- Strings used for enums for database portability; indexes on foreign keys and
  filtered columns (severity, status, category).
- Migration: `alembic revision --autogenerate -m "initial schema"` →
  `alembic upgrade head` (verified: creates all 10 tables).

## 4. API Endpoints

Verified at runtime (see README for the full table): `/api/health`,
`/api/auth/{register,login,me}`, `/api/targets` CRUD, `/api/scans`
(create/list/detail/cancel/delete), `/api/findings` (list/get/status), 
`/api/reports` (list/generate/download/delete), `/api/dashboard/summary`.
Errors use `{"error": {"code", "detail"}}`; body validation returns 422.

## 5. Security Controls (implemented + tested)

| Control | Where | Tested by |
|---|---|---|
| Input validation (targets, ports, usernames, passwords) | `utils/validation.py` | `test_validation.py`, `test_targets.py` |
| Secure subprocess (arg arrays, no shell) | `scanners/nmap_scanner.py` | code review + parser tests |
| SQL injection prevention (ORM-only queries) | all services | review |
| XSS-safe rendering | frontend `esc()`, no inline scripts | static check (`grep <script>`) |
| CORS restrictions | `main.py` | `test_health.py::test_cors_header_echoed` |
| Security headers + CSP | `security/headers.py` | `test_health.py::test_security_headers_present` |
| Rate limiting (general + auth) | `security/rate_limit.py` | exercised in suite |
| Request size limit (1 MB → 413) | `security/middleware.py` | `test_health.py::test_oversized_body_rejected` |
| Error sanitization (no stack traces) | `utils/errors.py` | `test_health.py::test_no_stack_trace...` |
| Secure logging (redaction) | `utils/logging.py` | review |
| No secret leakage | `.env` config, redaction | review |
| File path validation + PDF name sanitization | `api/reports.py`, `utils/validation.py` | `test_reports.py` |
| Password hashing (bcrypt), JWT | `utils/security.py` | `test_auth.py` |

## 6. Scanner Modules

- **nmap_scanner.py** — `nmap -sT -sV -Pn --open <top-ports|-p> -oX - <target>`;
  Popen + timeout + kill; XML size cap; engine reports `nmap`.
- **fallback_scanner.py** — socket `connect()` probes (bounded, thread-pooled,
  rate-safe); engine reports `basic`. Used automatically when nmap is missing
  (this machine has no nmap, so the live workflow exercised this engine).
- **web_scanner.py** — requests with connect/read timeouts, redirect handling,
  2 MB body cap, header/technology collection.
- **tls_scanner.py** — strict then unverified handshakes, `cryptography` cert
  parsing, legacy-protocol probe.
- **directory_scanner.py** — delay-limited wordlist probing, max paths.
- **checks.py** — OWASP-aligned findings with consistent severity rules.
- **runner.py** — orchestrates modules, persists results, computes risk.

## 7. Testing Results

```
$ pytest
117 passed in 12.05s

$ python -m compileall app tests scripts
COMPILEALL_OK
```

Plus a **live end-to-end validation** (real server + background job manager +
local lab on 127.0.0.1:8080): 15/15 checks passed — health, register, login,
target creation, queued scan → COMPLETED via the background worker, risk score
8.0, 1 host / 1 open port / 12 findings (1 HIGH, 3 MEDIUM, 5 LOW, 3 INFO),
security-headers + insecure-cookie + directory-discovery + information-
disclosure categories present, PDF report generated and downloaded (13 KB),
dashboard totals correct.

## 8. Known Limitations

- **nmap not installed in the verification environment** — scans used the
  built-in scanner (`basic` engine). The nmap integration (arg arrays, XML
  parsing) is implemented and unit-tested via fixture XML, and will engage
  automatically once nmap is installed; it was not exercised against a live
  binary here.
- CVSS scores are base-score estimates, not official NVD/CVE data.
- Fixed wordlist for directory discovery; port scans capped at 1024 ports.
- In-memory rate limiting (single-process); a shared store is recommended for
  multi-worker deployments.
- Frontend browser automation was blocked by an agent infrastructure error;
  the frontend was verified via JS syntax checks, asset resolution, CSP
  compatibility (no inline scripts), and the live API workflow.

## 9. Future Improvements

CVE lookup with attribution, scheduled scans with delta reporting, alerting
(webhook/email), report trend analysis, RBAC/teams, OAuth2 SSO, Docker Compose
deployment, custom wordlists.

## 10. Deployment Readiness

- **Development:** fully working (SQLite + auto-create tables).
- **Production path:** set `SECRET_KEY`, `APP_ENV=production`, a PostgreSQL
  `DATABASE_URL`, `CORS_ORIGINS`, run `alembic upgrade head`, and serve behind
  a TLS-terminating reverse proxy (the app emits HSTS and security headers).
- The `validate_for_production()` guard refuses to start with the default
  secret outside development.
