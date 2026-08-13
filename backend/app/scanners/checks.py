"""OWASP-aligned SAFE checks.

Each check inspects observed evidence and produces FindingData entries with
consistent severity rules. These are configuration/reconnaissance checks only —
no exploitation, no credential testing, no destructive actions.
"""

import re
from typing import Optional

from app.models.enums import FindingSeverity
from app.scanners.base import DirEntry, FindingData, PortData, TLSResult, WebResult
from app.services.finding_service import REMEDIATION_TEMPLATES

# ---------------------------------------------------------------------------
# Security header checks (OWASP Security Headers guidance)
# ---------------------------------------------------------------------------

_EXPECTED_HEADERS: dict[str, tuple[FindingSeverity, str, str]] = {
    "content-security-policy": (
        FindingSeverity.MEDIUM,
        "Missing Content-Security-Policy header",
        "The response does not include a Content-Security-Policy header, so the "
        "application does not restrict the sources from which content may load. "
        "This increases the impact of stored/reflected XSS.",
    ),
    "strict-transport-security": (
        FindingSeverity.MEDIUM,
        "Missing Strict-Transport-Security header",
        "The response does not advertise HTTP Strict Transport Security (HSTS), "
        "leaving users open to protocol-downgrade and cookie-hijacking attacks.",
    ),
    "x-content-type-options": (
        FindingSeverity.LOW,
        "Missing X-Content-Type-Options header",
        "The X-Content-Type-Options: nosniff header is not set, so browsers may "
        "MIME-sniff responses and execute content of an unexpected type.",
    ),
    "x-frame-options": (
        FindingSeverity.MEDIUM,
        "Missing X-Frame-Options header",
        "The response does not include X-Frame-Options (and no frame-ancestors "
        "CSP directive was observed), allowing clickjacking of the page.",
    ),
    "referrer-policy": (
        FindingSeverity.LOW,
        "Missing Referrer-Policy header",
        "No Referrer-Policy is set, so the browser default may leak the full "
        "URL (including query strings) to third-party origins.",
    ),
}


def check_security_headers(web: WebResult) -> list[FindingData]:
    findings: list[FindingData] = []
    is_https = web.url.startswith("https://")
    csp = web.headers.get("content-security-policy", "")

    for header, (severity, title, description) in _EXPECTED_HEADERS.items():
        if header == "strict-transport-security" and not is_https:
            continue  # HSTS only applies to HTTPS responses
        if header in web.headers:
            continue
        if header == "x-frame-options" and "frame-ancestors" in csp:
            continue  # CSP frame-ancestors is the modern replacement
        findings.append(
            FindingData(
                title=title,
                category="security-headers",
                severity=severity,
                description=description,
                evidence=f"GET {web.url} -> {web.status_code}; header '{header}' not present",
                affected_component=web.url,
                remediation=REMEDIATION_TEMPLATES["security-headers"],
                reference="https://owasp.org/www-project-secure-headers/",
            )
        )

    # Weak CSP directives.
    if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp) and "nonce-" not in csp:
        findings.append(
            FindingData(
                title="Content-Security-Policy uses unsafe-inline/unsafe-eval",
                category="security-headers",
                severity=FindingSeverity.LOW,
                description=(
                    "The Content-Security-Policy allows unsafe-inline or unsafe-eval "
                    "without a nonce, weakening XSS protections."
                ),
                evidence=f"Content-Security-Policy: {csp[:300]}",
                affected_component=web.url,
                remediation=(
                    "Replace unsafe-inline/unsafe-eval with nonce- or hash-based "
                    "allowlists where possible."
                ),
                reference="https://owasp.org/www-project-secure-headers/",
            )
        )
    return findings


def check_cookie_security(web: WebResult) -> list[FindingData]:
    """Cookie Secure / HttpOnly / SameSite checks."""
    findings: list[FindingData] = []
    for cookie in web.cookies:
        name = cookie.get("name", "?")
        flags = cookie.get("flags", {})
        parts = []
        if not flags.get("secure"):
            parts.append("Secure")
        if not flags.get("httponly"):
            parts.append("HttpOnly")
        if not flags.get("samesite"):
            parts.append("SameSite")
        if not parts:
            continue
        findings.append(
            FindingData(
                title=f"Cookie '{name}' missing security attributes: {', '.join(parts)}",
                category="insecure-cookie",
                severity=FindingSeverity.MEDIUM,
                description=(
                    f"The cookie '{name}' is missing {', '.join(parts)}. This "
                    "increases exposure to interception, XSS-based theft and "
                    "CSRF attacks."
                ),
                evidence=f"Set-Cookie observed for '{name}'; missing: {', '.join(parts)}",
                affected_component=web.url,
                remediation=REMEDIATION_TEMPLATES["insecure-cookie"],
                reference="https://owasp.org/www-community/controls/SecureCookieAttribute",
            )
        )
    return findings


def check_info_disclosure(web: WebResult) -> list[FindingData]:
    """Banner/version disclosure checks (basic information disclosure)."""
    findings: list[FindingData] = []
    server = web.headers.get("server", "")
    powered = web.headers.get("x-powered-by", "")

    if server and re.search(r"\d+\.\d+", server):
        findings.append(
            FindingData(
                title="Web server version disclosure",
                category="information-disclosure",
                severity=FindingSeverity.LOW,
                description=(
                    "The Server header discloses the web server software and "
                    "version, aiding attackers in selecting known exploits."
                ),
                evidence=f"Server: {server}",
                affected_component=web.url,
                remediation=REMEDIATION_TEMPLATES["information-disclosure"],
                reference="https://owasp.org/www-project-web-security-testing-guide/",
            )
        )
    if powered:
        findings.append(
            FindingData(
                title="X-Powered-By header discloses technology stack",
                category="information-disclosure",
                severity=FindingSeverity.LOW,
                description=(
                    "The X-Powered-By header reveals the underlying framework or "
                    "language to unauthenticated users."
                ),
                evidence=f"X-Powered-By: {powered}",
                affected_component=web.url,
                remediation=REMEDIATION_TEMPLATES["information-disclosure"],
            )
        )
    return findings


def check_technologies(web: WebResult) -> list[FindingData]:
    """Record detected technologies as informational findings."""
    if not web.technologies:
        return []
    return [
        FindingData(
            title=f"Detected technology: {', '.join(web.technologies)}",
            category="technology-detection",
            severity=FindingSeverity.INFO,
            description=(
                "Passive fingerprinting identified the following technologies on "
                "the target: " + ", ".join(web.technologies) + "."
            ),
            evidence=f"GET {web.url} headers",
            affected_component=web.url,
            remediation=(
                "Review identified versions against known vulnerabilities; keep "
                "all components patched."
            ),
        )
    ]


# ---------------------------------------------------------------------------
# TLS checks
# ---------------------------------------------------------------------------

def check_tls(result: TLSResult, affected_component: str) -> list[FindingData]:
    findings: list[FindingData] = []

    if not result.connected:
        return findings

    if result.days_to_expiry is not None and result.days_to_expiry < 0:
        findings.append(
            FindingData(
                title="TLS certificate is expired",
                category="tls",
                severity=FindingSeverity.HIGH,
                description=(
                    "The server presents an expired TLS certificate, which breaks "
                    "trust for all clients and can indicate a mis-managed service."
                ),
                evidence=f"not_after={result.not_after}",
                affected_component=affected_component,
                remediation=REMEDIATION_TEMPLATES["tls"],
                reference="https://owasp.org/www-project-web-security-testing-guide/",
            )
        )
    elif result.days_to_expiry is not None and result.days_to_expiry < 30:
        findings.append(
            FindingData(
                title="TLS certificate expires soon",
                category="tls",
                severity=FindingSeverity.LOW,
                description=(
                    f"The TLS certificate expires in {int(result.days_to_expiry)} days."
                ),
                evidence=f"not_after={result.not_after}",
                affected_component=affected_component,
                remediation="Renew the certificate before expiry.",
            )
        )

    if result.hostname_mismatch:
        findings.append(
            FindingData(
                title="TLS certificate hostname mismatch",
                category="tls",
                severity=FindingSeverity.HIGH,
                description=(
                    "The certificate is not valid for the requested hostname, "
                    "causing client-side verification failures and enabling "
                    "on-path interception."
                ),
                evidence=f"subject={result.subject}; SAN={result.san}",
                affected_component=affected_component,
                remediation=REMEDIATION_TEMPLATES["tls"],
            )
        )

    if result.self_signed:
        findings.append(
            FindingData(
                title="TLS certificate is self-signed",
                category="tls",
                severity=FindingSeverity.MEDIUM,
                description=(
                    "The server uses a self-signed certificate; clients cannot "
                    "verify the identity of the service without manual trust."
                ),
                evidence=f"subject={result.subject}; issuer={result.issuer}",
                affected_component=affected_component,
                remediation=REMEDIATION_TEMPLATES["tls"],
            )
        )

    if result.legacy_tls_supported:
        findings.append(
            FindingData(
                title="Legacy TLS versions (1.0/1.1) supported",
                category="tls",
                severity=FindingSeverity.HIGH,
                description=(
                    "The server accepts TLS 1.0 or 1.1 handshakes. These protocol "
                    "versions are deprecated and vulnerable to downgrade attacks."
                ),
                evidence="TLS 1.0/1.1 handshake succeeded",
                affected_component=affected_component,
                remediation=REMEDIATION_TEMPLATES["tls"],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Port / service checks
# ---------------------------------------------------------------------------

_RISKY_SERVICES = {
    "telnet": (
        FindingSeverity.MEDIUM,
        "Insecure remote administration service exposed",
        "Telnet transmits credentials and data in cleartext.",
    ),
    "ftp": (
        FindingSeverity.MEDIUM,
        "Cleartext FTP service exposed",
        "FTP transmits credentials and data in cleartext.",
    ),
    "rlogin": (FindingSeverity.MEDIUM, "Legacy rlogin service exposed", ""),
    "snmp": (FindingSeverity.MEDIUM, "SNMP service exposed", ""),
    "vnc": (FindingSeverity.MEDIUM, "VNC service exposed", ""),
}


def check_open_port(host_ip: str, port: PortData) -> FindingData:
    service = (port.service or "").lower()
    if service in _RISKY_SERVICES:
        severity, title, note = _RISKY_SERVICES[service]
        description = (
            f"The {port.service} service is open on {host_ip}:{port.port}. "
            f"{note}"
        ).strip()
        reference = "https://owasp.org/www-project-web-security-testing-guide/"
    else:
        severity = FindingSeverity.INFO
        title = f"Open port {port.port} exposed"
        description = (
            f"TCP port {port.port} is open on {host_ip} and responds. The "
            "service should be reviewed to confirm it is required and restricted."
        )
        reference = None

    version_note = f" ({port.product} {port.version})" if (port.product or port.version) else ""
    return FindingData(
        title=title,
        category="exposed-service",
        severity=severity,
        description=description,
        evidence=f"{host_ip}:{port.port}/tcp open - {port.service or 'unknown'}{version_note}",
        affected_component=f"{host_ip}:{port.port}",
        remediation=REMEDIATION_TEMPLATES["exposed-service"],
        reference=reference,
    )


# ---------------------------------------------------------------------------
# Directory discovery checks
# ---------------------------------------------------------------------------

_SENSITIVE_PATH_PATTERNS: list[tuple[str, FindingSeverity]] = [
    (".git", FindingSeverity.HIGH),
    ("backup", FindingSeverity.MEDIUM),
    ("phpmyadmin", FindingSeverity.MEDIUM),
    ("jenkins", FindingSeverity.MEDIUM),
    ("console", FindingSeverity.MEDIUM),
    ("debug", FindingSeverity.MEDIUM),
    ("server-status", FindingSeverity.MEDIUM),
    ("config", FindingSeverity.LOW),
    ("admin", FindingSeverity.LOW),
    ("login", FindingSeverity.LOW),
    ("uploads", FindingSeverity.LOW),
    ("test", FindingSeverity.LOW),
    ("dev", FindingSeverity.LOW),
    ("api", FindingSeverity.INFO),
    ("docs", FindingSeverity.INFO),
]


def check_directory_entry(host_ip: str, entry: DirEntry) -> FindingData:
    path = entry.url.split("/", 3)[-1].lower()
    severity = FindingSeverity.INFO
    for pattern, sev in _SENSITIVE_PATH_PATTERNS:
        if pattern in path:
            severity = sev
            break

    title = f"Discovered path returned HTTP {entry.status_code}"
    if severity.value in ("HIGH", "MEDIUM"):
        title = f"Sensitive path exposed: /{path}"

    return FindingData(
        title=title,
        category="directory-discovery",
        severity=severity,
        description=(
            f"The path '{entry.url}' is accessible (HTTP {entry.status_code}). "
            "Review whether it should be publicly reachable."
        ),
        evidence=(
            f"{entry.url} -> {entry.status_code} "
            f"(content_length={entry.content_length}, type={entry.content_type or 'n/a'})"
        ),
        affected_component=entry.url,
        remediation=REMEDIATION_TEMPLATES["directory"],
    )
