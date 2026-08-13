# CyberSentinel

**Automated Vulnerability Assessment & Security Reporting Platform**

CyberSentinel is a portfolio-grade cybersecurity platform that performs safe,
non-destructive vulnerability assessments against **explicitly authorized
targets** (localhost, private labs, CTF/lab machines, intentionally vulnerable
applications) and produces professional PDF security reports.

> ⚠️ **AUTHORIZATION WARNING**
>
> This tool must **only** be used against systems you own or have explicit
> written authorization to assess. Scanning systems without permission may be
> illegal in your jurisdiction. CyberSentinel deliberately excludes destructive
> exploitation, credential brute-forcing, denial-of-service, malware/persistence
> and stealth/evasion capabilities, and by default **refuses to scan public
> (global) IP addresses**.

---

## Features

| Area | Capabilities |
|---|---|
| **Target management** | Strict IP/hostname validation, ownership isolation, lab scope enforcement |
| **Port discovery** | Nmap TCP connect + version detection (safe arg-array subprocess, XML parsing), built-in TCP connect scanner fallback when nmap is absent |
| **Web checks** | Security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy), cookie Secure/HttpOnly/SameSite, banner & tech disclosure |
| **TLS analysis** | Certificate validity, expiry, hostname match, self-signed detection, legacy TLS 1.0/1.1 probe |
| **Directory discovery** | Bounded, rate-limited wordlist probing (max paths, no recursion) |
| **Finding engine** | Unified finding format with severity, CVSS v3.1 base scores, evidence, remediation and references |
| **Risk scoring** | Transparent CVSS v3.1 implementation with documented metric assumptions |
| **Scan management** | QUEUED / RUNNING / COMPLETED / FAILED / CANCELLED lifecycle, background job queue, concurrency limits, cancellation |
| **Reporting** | Professional ReportLab PDF: cover, executive summary, scope, methodology, hosts/ports/services, severity distribution, detailed findings with evidence, CVSS, remediation, limitations — plus on-the-fly **CSV** (findings table, spreadsheet-formula-injection safe) and **JSON** (full structured) exports |
| **Dashboard** | Dark SOC-themed UI with charts (Chart.js), filters, live scan status |
| **Authentication** | bcrypt password hashing, JWT sessions, per-user data isolation |
| **Hardening** | CORS, security headers, per-IP rate limiting, request size limits, input validation, sanitized errors, redacted logging, path-traversal-safe downloads |

---

## Tech Stack

- **Backend:** Python 3.12+, FastAPI, Uvicorn, Pydantic v2, SQLAlchemy 2.0, Alembic
- **Scanners:** Nmap (subprocess + XML), Requests, Python `ssl` + `cryptography`
- **Database:** SQLite (development), PostgreSQL-ready via `DATABASE_URL`
- **Frontend:** HTML, CSS, vanilla JavaScript, Chart.js (CDN)
- **Reporting:** ReportLab
- **Testing:** pytest, FastAPI TestClient

---

## Architecture

```
cybersentinel/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI app, middleware, static frontend mount
│   │   ├── config.py          # pydantic-settings environment configuration
│   │   ├── database.py        # SQLAlchemy engine/session/Base
│   │   ├── models/            # users, targets, scans, hosts, ports, services,
│   │   │                      # findings, evidence, remediations, reports
│   │   ├── schemas/           # Pydantic request/response models
│   │   ├── api/               # auth, targets, scans, findings, reports, dashboard
│   │   ├── services/          # auth, targets, scans, findings, risk (CVSS),
│   │   │                      # dashboard, reports
│   │   ├── scanners/          # nmap, nmap_parser, web, tls, directory, checks, runner
│   │   ├── security/          # rate limiting, security headers, size limits
│   │   ├── reports/           # ReportLab PDF generator + CSV/JSON exporters
│   │   └── utils/             # logging (redaction), errors, validation, security
│   ├── alembic/               # database migrations
│   ├── scripts/               # local_lab.py, e2e_live.py, smoke_api.py
│   ├── tests/                 # 123 pytest tests
│   ├── requirements.txt
│   └── .env.example
├── frontend/                  # dashboard, targets, scans, findings, reports, settings
├── reports/                   # generated PDFs
├── README.md
└── CyberSentinel-Development-Report.md
```

**Key design decisions**

- **Safe subprocess execution** — nmap is invoked with an explicit argument
  array (`shell=False`), a hard timeout, process-group cleanup, an XML output
  size cap, and never with string-built commands.
- **Safety policy** — scanning public/global IPs is disabled by default
  (`ALLOW_EXTERNAL_TARGETS=false`); an optional `ALLOWED_TARGETS` allowlist can
  scope assessments further.
- **Honest scan engine** — if nmap is not installed, scans fall back to a
  built-in, rate-limited TCP connect scanner and the engine used is recorded on
  every scan (`nmap` or `basic`).
- **Transparent risk scoring** — CVSS v3.1 base scores are computed from
  explicit metric assumptions; CyberSentinel never claims official CVE/NVD data.

---

## Installation

### 1. Prerequisites

- Python **3.12+** (tested on 3.13)
- **Nmap** (optional — the platform falls back to a built-in scanner without it)

  - Windows: download from https://nmap.org/download.html (ensure `nmap` is on PATH)
  - macOS: `brew install nmap`
  - Debian/Ubuntu: `sudo apt install nmap`

### 2. Backend setup

```bash
cd backend
python -m venv .venv
# Windows:  .venv\Scripts\activate        macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # then edit SECRET_KEY and other settings
```

### 3. Database setup

SQLite works immediately (the app creates tables automatically in development):

```bash
# Optional: manage the schema with Alembic instead
python -m alembic revision --autogenerate -m "initial schema"
python -m alembic upgrade head
```

For PostgreSQL set `DATABASE_URL` in `.env`, e.g.
`postgresql+psycopg://user:password@localhost:5432/cybersentinel`.

### 4. Run

```bash
cd backend
uvicorn app.main:app --reload
```

- API + dashboard: http://127.0.0.1:8000
- Interactive API docs: http://127.0.0.1:8000/api/docs
- Health check: http://127.0.0.1:8000/api/health → `{"status": "ok"}`

---

## How to Perform a Local Lab Scan

```bash
# Terminal 1 — start the intentionally-vulnerable local lab (loopback only)
cd backend
python scripts/local_lab.py --port 8080

# Terminal 2 — start CyberSentinel
cd backend
uvicorn app.main:app --port 8000
```

Then in the web UI (http://127.0.0.1:8000):

1. **Create an account** and sign in.
2. **Targets → + Add target** → `127.0.0.1` (or `localhost`).
3. **New Scan** → choose the target, `Full assessment`, port range `8080-8080`
   (or `top-1000`), **Launch scan**.
4. Watch the scan progress; when it completes, open the scan detail to see the
   risk score, hosts, open ports and findings.
5. **Findings** → inspect the unified findings (security headers, insecure
   cookie, banner disclosure, `.git/config` exposure, etc.).
6. **Reports** → generate `CyberSentinel-Report-{scan_id}.pdf` and download it,
   or export the findings as **JSON** / **CSV** from the same row.

An automated end-to-end check of this exact flow:

```bash
cd backend
python scripts/local_lab.py --port 8080 &   # terminal 1
uvicorn app.main:app --port 8000 &          # terminal 2
python scripts/e2e_live.py                  # runs the full workflow
```

---

## API Reference

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Health check |
| POST | `/api/auth/register` | Create account |
| POST | `/api/auth/login` | Sign in (returns JWT) |
| GET | `/api/auth/me` | Current user |
| GET/POST | `/api/targets` | List / create targets |
| GET/PATCH/DELETE | `/api/targets/{id}` | View / update / delete target |
| POST | `/api/scans` | Queue a scan (`target_id`, `scan_type`, `port_range`) |
| GET | `/api/scans` | List scans |
| GET | `/api/scans/{id}` | Scan detail (hosts, ports, summary) |
| POST | `/api/scans/{id}/cancel` | Cancel a queued/running scan |
| DELETE | `/api/scans/{id}` | Delete a scan |
| GET | `/api/findings` | List findings (filters: severity, category, host, status, scan_id) |
| GET | `/api/findings/{id}` | Finding detail |
| PATCH | `/api/findings/{id}/status` | Update finding status |
| GET | `/api/reports` | List reports |
| POST | `/api/reports/scans/{scan_id}` | Generate PDF report |
| GET | `/api/reports/{id}/download` | Download PDF |
| GET | `/api/reports/{id}/export?format=json` | Export report as JSON (full structured data) |
| GET | `/api/reports/{id}/export?format=csv` | Export findings as CSV (formula-injection safe) |
| DELETE | `/api/reports/{id}` | Delete report |
| GET | `/api/dashboard/summary` | Dashboard aggregates |

**Scan types:** `full` | `ports` | `web` | `tls` | `directories`
**Port ranges:** `top-100` | `top-1000` | numeric ranges bounded to ≤ 1024 ports

Errors use a consistent envelope: `{"error": {"code": ..., "detail": ...}}`.

---

## Security Considerations

- **Auth:** bcrypt (cost 12) password hashing, JWT access tokens, per-user data
  isolation enforced in every service.
- **Input validation:** target addresses accept only IPs/hostnames; shell
  metacharacters, whitespace and path separators are rejected; port ranges are
  bounded; usernames/passwords validated.
- **Subprocess safety:** nmap runs with argument arrays, `shell=False`,
  timeout, process cleanup and output size caps.
- **Web app hardening:** restrictive CORS, security headers (CSP, HSTS,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy),
  per-IP rate limiting (login stricter), 1 MB request body limit, sanitized
  error responses (no stack traces), redacted logging (tokens/secrets scrubbed),
  path-traversal-safe report downloads, XSS-safe frontend rendering.
- **No destructive features:** no exploitation, brute-forcing, DoS,
  persistence, malware, or stealth/evasion.
- **Scope enforcement:** public IP scans blocked by default; `ALLOWED_TARGETS`
  allowlist; `localhost` and RFC1918 private addresses allowed for labs.

---

## Testing

```bash
cd backend
pytest                 # 123 tests, ~12 s
python -m compileall app tests scripts
```

Coverage includes: health API, authentication (hashing, JWT, isolation), target
validation (injection attempts rejected), scan API (states, scope policy,
validation), CVSS v3.1 scoring (known vectors), finding engine (dedup,
filters, status), nmap XML parsing, web/TLS/directory checks against a local
lab server, PDF report generation + CSV/JSON export (incl. spreadsheet-formula
injection sanitization), dashboard aggregation, and a full end-to-end local-lab
workflow.

---

## Screenshots

| | |
|---|---|
| Login (dark SOC theme) | Dashboard with severity & risk charts |
| Targets & New Scan | Scan detail with risk gauge, hosts, ports |
| Findings with filters & detail modal | PDF report generation |

*(Screenshots to be added — run the app and capture the pages above.)*

---

## Known Limitations

- Without nmap installed, scans use the built-in TCP connect scanner (`basic`
  engine) which does not perform OS fingerprinting or deep version detection.
- CVSS scores are **base-score estimates** computed by CyberSentinel from
  observed evidence — not official NVD/CVE data.
- Directory discovery uses a small fixed wordlist; it is not exhaustive.
- Port scans are bounded (≤ 1024 ports); services on unscanned ports are not
  assessed.
- Web/TLS checks require the target to respond to standard HTTP(S); non-HTTP
  protocols are only enumerated.
- Rate limiting is in-memory (per-process); a shared store (e.g. Redis) is
  recommended for multi-process production deployments.

---

## Future Improvements

- Full CVE lookup integration (with attribution to an official source)
- Email/Slack/Webhook alerting for new findings
- Scheduled/recurring scans with delta reporting
- Report history diffing and trend charts
- OAuth2 SSO, role-based access control, team workspaces
- Custom directory-discovery wordlists per target
- Docker Compose deployment with PostgreSQL

---

## License & Disclaimer

Educational / portfolio use. **You are responsible for ensuring you have
authorization before assessing any system.** This software provides no
guarantee of security and is provided "as is".
