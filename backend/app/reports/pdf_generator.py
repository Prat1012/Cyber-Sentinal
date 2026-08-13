"""Professional PDF report generation (ReportLab).

Produces ``CyberSentinel-Report-{scan_id}.pdf`` with cover page, executive
summary, scope, methodology, scan summary, hosts/ports/services/technologies,
vulnerability summary, severity distribution, detailed findings with evidence,
CVSS scores and remediation, limitations and an assessment timestamp.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from app.models.finding import Finding
from app.models.host import Host
from app.models.scan import Scan
from app.models.target import Target
from app.utils.validation import sanitize_filename

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#d92d20"),
    "HIGH": colors.HexColor("#f79009"),
    "MEDIUM": colors.HexColor("#facc15"),
    "LOW": colors.HexColor("#36bffa"),
    "INFO": colors.HexColor("#98a2b3"),
}

DARK = colors.HexColor("#0b1220")
ACCENT = colors.HexColor("#0ea5e9")
LIGHT = colors.HexColor("#eef2f7")


def _styles():
    base = getSampleStyleSheet()
    styles = {
        "Title": ParagraphStyle("TitleX", parent=base["Title"], textColor=colors.white, fontSize=26, leading=30, alignment=TA_CENTER, spaceAfter=6),
        "Subtitle": ParagraphStyle("SubtitleX", parent=base["Normal"], textColor=ACCENT, fontSize=13, alignment=TA_CENTER),
        "H1": ParagraphStyle("H1X", parent=base["Heading1"], textColor=ACCENT, fontSize=16, spaceBefore=14, spaceAfter=6),
        "H2": ParagraphStyle("H2X", parent=base["Heading2"], textColor=DARK, fontSize=12, spaceBefore=10, spaceAfter=4),
        "Body": ParagraphStyle("BodyX", parent=base["BodyText"], fontSize=9.5, leading=13),
        "Small": ParagraphStyle("SmallX", parent=base["BodyText"], fontSize=8, leading=10, textColor=colors.HexColor("#667085")),
        "Cover": ParagraphStyle("CoverX", parent=base["Normal"], textColor=colors.white, fontSize=10, leading=14, alignment=TA_CENTER),
    }
    return styles


def generate_pdf_report(
    scan: Scan,
    target: Target,
    hosts: list[Host],
    findings: list[Finding],
    output_dir: Path,
    author: Optional[str] = None,
) -> Path:
    """Generate the PDF and return its path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = f"CyberSentinel-Report-{scan.id}.pdf"
    safe_filename = sanitize_filename(filename)
    output_path = output_dir / safe_filename

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"CyberSentinel Report - {target.address}",
        author=author or "CyberSentinel",
    )

    story = _build_story(scan, target, hosts, findings, author)
    doc.build(story, onFirstPage=_cover_page, onLaterPages=_page_footer)
    logger.info("Generated report %s", output_path)
    return output_path


def _cover_page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(DARK)
    canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
    canvas.setFillColor(ACCENT)
    canvas.rect(0, A4[1] - 4 * mm, A4[0], 4 * mm, fill=1, stroke=0)
    canvas.restoreState()


def _page_footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(LIGHT)
    canvas.setLineWidth(0.5)
    canvas.line(18 * mm, 12 * mm, A4[0] - 18 * mm, 12 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#667085"))
    canvas.drawString(18 * mm, 8 * mm, "CyberSentinel - Authorized Security Assessment")
    canvas.drawRightString(A4[0] - 18 * mm, 8 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _build_story(scan: Scan, target: Target, hosts: list[Host], findings: list[Finding], author: Optional[str]) -> list:
    s = _styles()
    story: list = []

    # --- Cover ---
    story.append(Spacer(1, 120 * mm))
    story.append(Paragraph("CYBERSENTINEL", s["Title"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Automated Vulnerability Assessment &amp; Security Reporting", s["Subtitle"]))
    story.append(Spacer(1, 20 * mm))
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    story.append(Paragraph(f"Assessment Timestamp: {generated_at}", s["Cover"]))
    if author:
        story.append(Paragraph(f"Prepared by: {author}", s["Cover"]))
    story.append(Paragraph(f"Scan ID: {scan.id}", s["Cover"]))
    story.append(PageBreak())

    # --- Executive Summary ---
    story.append(Paragraph("Executive Summary", s["H1"]))
    by_severity = _severity_counts(findings)
    total_findings = len(findings)
    risk_score = scan.risk_score or 0.0
    story.append(Paragraph(
        f"This report summarizes a security assessment of <b>{target.address}</b> "
        f"performed on {_fmt(scan.requested_at)}. The assessment identified "
        f"<b>{total_findings}</b> finding(s) with an overall risk score of "
        f"<b>{risk_score:.1f}</b> (CVSS v3.1 scale).",
        s["Body"],
    ))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        "Severity distribution: "
        + ", ".join(f"{sev} {by_severity.get(sev, 0)}" for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")),
        s["Body"],
    ))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        "Findings in this report are configuration and reconnaissance observations "
        "obtained through safe, non-destructive checks against an explicitly "
        "authorized target.", s["Body"],
    ))

    # --- Scope ---
    story.append(Paragraph("Assessment Scope", s["H1"]))
    story.append(Paragraph(
        f"Target: <b>{target.address}</b> ({target.address_type})<br/>"
        f"Scan type: {scan.scan_type}<br/>"
        f"Port range: {scan.port_range}<br/>"
        f"Scan engine: {scan.scan_engine or 'n/a'}<br/>"
        f"Status: {scan.status}",
        s["Body"],
    ))

    # --- Methodology ---
    story.append(Paragraph("Methodology", s["H1"]))
    story.append(Paragraph(
        "1. <b>Port discovery</b> - TCP port enumeration and version detection (nmap "
        "TCP connect scan or built-in scanner).<br/>"
        "2. <b>Web assessment</b> - HTTP response inspection for security headers, "
        "cookie attributes, banner disclosure and technology fingerprinting.<br/>"
        "3. <b>TLS analysis</b> - certificate validity, expiry, hostname match and "
        "legacy protocol support.<br/>"
        "4. <b>Directory discovery</b> - bounded, rate-limited probing of a small "
        "wordlist.<br/>"
        "5. <b>Risk scoring</b> - CVSS v3.1 base scores computed from observed "
        "evidence; overall risk is the highest finding score.",
        s["Body"],
    ))

    # --- Scan Summary ---
    story.append(Paragraph("Scan Summary", s["H1"]))
    summary_table = Table(
        [
            ["Attribute", "Value"],
            ["Scan ID", str(scan.id)],
            ["Target", target.address],
            ["Started", _fmt(scan.started_at)],
            ["Completed", _fmt(scan.completed_at)],
            ["Duration", f"{scan.duration_seconds or 0:.1f}s" if scan.duration_seconds else "n/a"],
            ["Status", scan.status],
            ["Hosts discovered", str(len(hosts))],
            ["Open ports", str(sum(len(h.ports) for h in hosts))],
            ["Total findings", str(total_findings)],
            ["Overall risk score", f"{risk_score:.1f}"],
        ],
        colWidths=[70 * mm, 95 * mm],
    )
    summary_table.setStyle(_table_style())
    story.append(summary_table)
    story.append(Spacer(1, 4 * mm))

    # --- Hosts & ports ---
    story.append(Paragraph("Hosts, Ports and Services", s["H1"]))
    for host in hosts:
        story.append(Paragraph(
            f"<b>{host.ip_address}</b>"
            + (f" ({host.hostname})" if host.hostname else "")
            + f" - {host.status}"
            + (f" - OS: {host.os_guess}" if host.os_guess else ""),
            s["H2"],
        ))
        if not host.ports:
            story.append(Paragraph("No open ports found.", s["Body"]))
            continue
        rows = [["Port", "Protocol", "State", "Service", "Product/Version"]]
        for port in host.ports:
            rows.append([
                str(port.port),
                port.protocol,
                port.state,
                port.service or "",
                " ".join(filter(None, [port.product, port.version])),
            ])
        port_table = Table(rows, colWidths=[18 * mm, 20 * mm, 18 * mm, 40 * mm, 69 * mm])
        port_table.setStyle(_table_style())
        story.append(port_table)
        story.append(Spacer(1, 3 * mm))

    # --- Technologies ---
    technologies = _scan_technologies(scan)
    if technologies:
        story.append(Paragraph("Technologies", s["H1"]))
        story.append(Paragraph(", ".join(technologies), s["Body"]))
        story.append(Spacer(1, 4 * mm))

    # --- Severity distribution ---
    story.append(Paragraph("Severity Distribution", s["H1"]))
    dist_rows = [["Severity", "Count"]]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        dist_rows.append([sev, str(by_severity.get(sev, 0))])
    dist_table = Table(dist_rows, colWidths=[80 * mm, 85 * mm])
    dist_style = _table_style()
    for i, sev in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"), start=1):
        dist_style.add("BACKGROUND", (0, i), (-1, i), _severity_bg(sev))
    dist_table.setStyle(dist_style)
    story.append(dist_table)
    story.append(Spacer(1, 4 * mm))

    # --- Detailed findings ---
    story.append(Paragraph("Detailed Findings", s["H1"]))
    if not findings:
        story.append(Paragraph("No findings were recorded for this scan.", s["Body"]))
    for i, finding in enumerate(findings, start=1):
        story.append(Paragraph(
            f"{i}. {finding.title} "
            f"[{finding.severity}]"
            + (f" - CVSS {finding.cvss_score:.1f}" if finding.cvss_score else ""),
            s["H2"],
        ))
        info = [
            ("Category", finding.category),
            ("Affected asset", finding.affected_asset or "n/a"),
            ("Affected component", finding.affected_component or "n/a"),
            ("Status", finding.status),
        ]
        info_rows = [[k, v] for k, v in info]
        info_table = Table(info_rows, colWidths=[45 * mm, 120 * mm])
        info_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), LIGHT),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(f"<b>Description:</b> {finding.description}", s["Body"]))
        if finding.evidence:
            story.append(Paragraph(f"<b>Evidence:</b> {finding.evidence}", s["Body"]))
        if finding.cvss_vector:
            story.append(Paragraph(f"<b>CVSS vector:</b> {finding.cvss_vector}", s["Body"]))
        if finding.remediation:
            story.append(Paragraph(f"<b>Remediation:</b> {finding.remediation}", s["Body"]))
        if finding.reference:
            story.append(Paragraph(f"<b>Reference:</b> {finding.reference}", s["Body"]))
        story.append(Spacer(1, 4 * mm))

    # --- Limitations ---
    story.append(Paragraph("Limitations", s["H1"]))
    story.append(Paragraph(
        "- This assessment was performed only against explicitly authorized targets "
        "using safe, non-destructive techniques.<br/>"
        "- Findings are configuration/reconnaissance observations; no exploitation "
        "or credential testing was performed.<br/>"
        "- CVSS scores are base-score estimates computed by CyberSentinel from "
        "observed evidence and are not official vendor/NVD data.<br/>"
        "- The port scan coverage is limited to the configured port range; services "
        "on un-scanned ports were not assessed.<br/>"
        "- This report does not guarantee the absence of vulnerabilities.",
        s["Body"],
    ))

    # --- Footer note ---
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        f"Generated by CyberSentinel on {generated_at}. "
        "Authorized use only - assessments require explicit permission from the system owner.",
        s["Small"],
    ))
    return story


def _scan_technologies(scan: Scan) -> list[str]:
    """Read detected technologies recorded in the scan summary JSON."""
    if not scan.summary_json:
        return []
    try:
        import json

        data = json.loads(scan.summary_json)
        return list(data.get("technologies", []))
    except (ValueError, TypeError):
        return []


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {sev: 0 for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _severity_bg(severity: str):
    return colors.HexColor({  # light tinted rows
        "CRITICAL": "#fdecea",
        "HIGH": "#fef3e2",
        "MEDIUM": "#fef9c3",
        "LOW": "#e0f2fe",
        "INFO": "#f1f5f9",
    }.get(severity, "#f1f5f9"))


def _table_style() -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ])


def _fmt(value: Optional[datetime]) -> str:
    if value is None:
        return "n/a"
    return value.strftime("%Y-%m-%d %H:%M UTC") if value.tzinfo else value.strftime("%Y-%m-%d %H:%M")
