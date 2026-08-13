"""Web scanner + OWASP-aligned check tests against a local lab server."""

from app.config import get_settings
from app.scanners.checks import (
    check_cookie_security,
    check_directory_entry,
    check_info_disclosure,
    check_security_headers,
)
from app.scanners.directory_scanner import DirectoryScanner
from app.scanners.web_scanner import WebScanner
from tests.lab_server import HTTP_PORT, LabHTTPServer

BASE_URL = f"http://127.0.0.1:{HTTP_PORT}"


def test_web_scanner_collects_metadata(lab_server):
    result = WebScanner(get_settings()).scan(BASE_URL)
    assert result is not None
    assert result.status_code == 200
    assert result.headers["server"] == "local-lab/1.0 (Python/3.13)"
    assert result.technologies  # Python detected from banner
    assert result.content_length > 0


def test_missing_security_headers_findings(lab_server):
    web = WebScanner(get_settings()).scan(BASE_URL)
    findings = check_security_headers(web)
    titles = {f.title for f in findings}
    # HSTS is skipped on plain http; the others should be flagged.
    assert "Missing Content-Security-Policy header" in titles
    assert "Missing X-Content-Type-Options header" in titles
    assert "Missing X-Frame-Options header" in titles
    assert "Missing Referrer-Policy header" in titles
    assert all(f.severity.value in ("LOW", "MEDIUM") for f in findings)


def test_insecure_cookie_finding(lab_server):
    web = WebScanner(get_settings()).scan(BASE_URL)
    findings = check_cookie_security(web)
    assert findings
    assert findings[0].category == "insecure-cookie"
    assert findings[0].severity.value == "MEDIUM"
    assert "Secure" in findings[0].title


def test_banner_version_disclosure_finding(lab_server):
    web = WebScanner(get_settings()).scan(BASE_URL)
    findings = check_info_disclosure(web)
    assert any(f.title == "Web server version disclosure" for f in findings)


def test_directory_discovery_finds_lab_paths(lab_server):
    entries = DirectoryScanner(get_settings()).scan(BASE_URL, max_paths=25, delay_seconds=0)
    found = {e.url for e in entries}
    assert f"{BASE_URL}/admin" in found
    assert f"{BASE_URL}/.git/config" in found
    assert f"{BASE_URL}/robots.txt" in found


def test_directory_check_severity_raises_for_git(lab_server):
    entries = DirectoryScanner(get_settings()).scan(BASE_URL, max_paths=25, delay_seconds=0)
    git = next(e for e in entries if ".git" in e.url)
    finding = check_directory_entry("127.0.0.1", git)
    assert finding.severity.value == "HIGH"
    assert finding.evidence
