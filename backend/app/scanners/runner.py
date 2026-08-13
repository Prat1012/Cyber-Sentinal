"""Scan orchestration.

Runs the appropriate scanner modules for an authorized target, collects
findings, persists hosts/ports/services/findings and computes the scan risk
score. This module is pure orchestration: database sessions are injected so it
can be unit-tested without a live HTTP server.
"""

import json
import logging
import time
from typing import Callable, Optional

from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.models.enums import FindingSeverity, ScanStatus, ScanType
from app.models.host import Host, Port, Service
from app.models.scan import Scan
from app.models.target import Target
from app.scanners.base import FindingData, HostData, PortData
from app.scanners.checks import (
    check_cookie_security,
    check_directory_entry,
    check_info_disclosure,
    check_open_port,
    check_security_headers,
    check_technologies,
    check_tls,
)
from app.scanners.directory_scanner import DirectoryScanner
from app.scanners.fallback_scanner import FallbackPortScanner
from app.scanners.nmap_scanner import NmapScanner
from app.scanners.tls_scanner import TLSScanner
from app.scanners.web_scanner import WebScanner
from app.services.finding_service import persist_findings
from app.services.risk_service import assess_scan_risk

logger = logging.getLogger(__name__)

WEB_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8081, 8088, 8443, 8888, 9000, 18080}


def execute_scan(
    scan_id: int,
    session_factory: Optional[Callable[[], Session]] = None,
    settings: Optional[Settings] = None,
) -> None:
    """Run one scan end-to-end. Safe to call from a worker thread."""
    factory = session_factory or _default_factory
    settings = settings or get_settings()
    db = factory()
    started = time.monotonic()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            logger.warning("Scan %s no longer exists; skipping job", scan_id)
            return
        if scan.status == ScanStatus.CANCELLED.value:
            return

        scan.status = ScanStatus.RUNNING.value
        scan.started_at = _now_utc()
        db.commit()

        try:
            target = db.get(Target, scan.target_id)
            if target is None:
                raise RuntimeError("Scan target no longer exists.")
            scan_type = ScanType(scan.scan_type) if scan.scan_type in ScanType._value2member_map_ else ScanType.FULL

            findings, hosts_data, engine, summary = run_assessment(
                target, scan_type, scan.port_range, settings
            )

            # Honour an in-flight cancellation: do not persist partial results.
            if scan.status == ScanStatus.CANCELLED.value:
                scan.completed_at = _now_utc()
                scan.duration_seconds = round(time.monotonic() - started, 2)
                db.commit()
                logger.info("Scan %s cancelled during execution", scan.id)
                return

            scan.scan_engine = engine

            host_lookup = _persist_hosts(db, scan, hosts_data)
            persist_findings(db, scan, findings, host_lookup)

            scores = [f.cvss_score or 0.0 for f in findings]
            scan.risk_score = assess_scan_risk(scores)
            summary.update(
                {
                    "hosts_count": len(hosts_data),
                    "open_ports_count": sum(len(h.ports) for h in hosts_data),
                    "findings_count": len(findings),
                    "findings_by_severity": _severity_counts(findings),
                    "engine": engine,
                    "target_address": target.address,
                }
            )
            scan.summary_json = json.dumps(summary)
            scan.status = ScanStatus.COMPLETED.value
            logger.info("Scan %s completed with risk score %s", scan.id, scan.risk_score)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Scan %s failed", scan.id)
            scan.status = ScanStatus.FAILED.value
            scan.error_message = _sanitize_error(exc)
        finally:
            scan.completed_at = _now_utc()
            scan.duration_seconds = round(time.monotonic() - started, 2)
            db.commit()
    finally:
        db.close()


def run_assessment(
    target: Target,
    scan_type: ScanType,
    port_range: str,
    settings: Settings,
) -> tuple[list[FindingData], list[HostData], str, dict]:
    """Perform the assessment and return (findings, hosts, engine, summary)."""
    address = target.address

    nmap = NmapScanner(settings)
    if nmap.available():
        engine = nmap.ENGINE_NAME
        hosts = nmap.scan(address, port_range=port_range)
    else:
        engine = FallbackPortScanner(settings).ENGINE_NAME
        logger.warning(
            "nmap not available; using built-in TCP connect scanner for %s", address
        )
        hosts = FallbackPortScanner(settings).scan(address, port_range=port_range)

    findings: list[FindingData] = []
    technologies: list[str] = []

    # Port-level findings.
    for host in hosts:
        for port in host.ports:
            if port.state == "open":
                findings.append(check_open_port(host.ip_address, port))

    # Web / TLS / directory modules.
    if scan_type in (ScanType.FULL, ScanType.WEB, ScanType.TLS, ScanType.DIRECTORIES):
        web_ports = _find_web_ports(hosts)
        for host in hosts:
            for port in web_ports.get(host.ip_address, []):
                scheme = "https" if (port.service == "https" or port.port in (443, 8443)) else "http"
                base_url = f"{scheme}://{_host_for_url(host, address)}:{port.port}"
                _run_web_modules(
                    findings, host.ip_address, base_url, port.port, scan_type, settings, technologies
                )

    summary = {
        "scan_type": scan_type.value,
        "engines": [engine],
        "technologies": sorted(set(technologies)),
    }
    return findings, hosts, engine, summary


def _run_web_modules(
    findings: list[FindingData],
    host_ip: str,
    base_url: str,
    port: int,
    scan_type: ScanType,
    settings: Settings,
    technologies: list[str],
) -> None:
    web = WebScanner(settings).scan(base_url)
    if web is None:
        return

    technologies.extend(web.technologies)

    if scan_type in (ScanType.FULL, ScanType.WEB):
        findings.extend(check_security_headers(web))
        findings.extend(check_cookie_security(web))
        findings.extend(check_info_disclosure(web))
        findings.extend(check_technologies(web))

    if scan_type in (ScanType.FULL, ScanType.DIRECTORIES):
        entries = DirectoryScanner(settings).scan(base_url)
        for entry in entries:
            findings.append(check_directory_entry(host_ip, entry))

    if web.url.startswith("https://") and scan_type in (ScanType.FULL, ScanType.TLS):
        tls = TLSScanner(settings).scan(host_ip, port)
        findings.extend(check_tls(tls, f"{host_ip}:{port}"))


def _find_web_ports(hosts: list[HostData]) -> dict[str, list[PortData]]:
    result: dict[str, list[PortData]] = {}
    for host in hosts:
        ports: list[PortData] = []
        for port in host.ports:
            if port.state != "open":
                continue
            service = (port.service or "").lower()
            if service in ("http", "https") or port.port in WEB_PORTS:
                ports.append(port)
        if ports:
            result[host.ip_address] = ports
    return result


def _host_for_url(host: HostData, target_address: str) -> str:
    # Prefer the IP for direct connections to avoid DNS surprises.
    return host.ip_address


def _persist_hosts(
    db: Session, scan: Scan, hosts_data: list[HostData]
) -> dict[str, int]:
    lookup: dict[str, int] = {}
    for data in hosts_data:
        host = Host(
            scan_id=scan.id,
            ip_address=data.ip_address,
            hostname=data.hostname,
            status=data.status,
            os_guess=data.os_guess,
            mac_address=data.mac_address,
            is_local=data.is_local,
        )
        db.add(host)
        db.flush()
        lookup[data.ip_address] = host.id

        for port in data.ports:
            port_row = Port(
                host_id=host.id,
                scan_id=scan.id,
                port=port.port,
                protocol=port.protocol,
                state=port.state,
                service=port.service,
                product=port.product,
                version=port.version,
                extra_json=json.dumps(port.extra) if port.extra else None,
            )
            db.add(port_row)
            db.flush()
            if port.service:
                db.add(
                    Service(
                        port_id=port_row.id,
                        name=port.service,
                        product=port.product,
                        version=port.version,
                        cpe=port.extra.get("cpe") if port.extra else None,
                    )
                )
    db.commit()
    return lookup


def _severity_counts(findings: list[FindingData]) -> dict[str, int]:
    counts = {s.value: 0 for s in FindingSeverity}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


def _sanitize_error(exc: Exception) -> str:
    message = str(exc).strip() or type(exc).__name__
    # Trim to a reasonable length and strip any linebreak noise.
    return message[:500].replace("\n", " ")


def _now_utc():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


def _default_factory():
    from app.database import SessionLocal

    return SessionLocal()
