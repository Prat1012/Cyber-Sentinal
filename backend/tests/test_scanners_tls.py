"""TLS scanner tests against a local self-signed TLS server."""

from app.config import get_settings
from app.scanners.checks import check_tls
from app.scanners.tls_scanner import TLSScanner
from tests.lab_server import TLS_PORT, LabTLSServer

HOST = "127.0.0.1"


def test_tls_scanner_detects_self_signed_cert(tls_server):
    result = TLSScanner(get_settings()).scan(HOST, TLS_PORT)
    assert result.connected is True
    assert result.self_signed is True
    assert result.cert_valid is False  # verification fails for self-signed
    assert result.subject and result.issuer
    assert result.days_to_expiry is not None and result.days_to_expiry > 0


def test_tls_checks_generate_self_signed_finding(tls_server):
    result = TLSScanner(get_settings()).scan(HOST, TLS_PORT)
    findings = check_tls(result, f"{HOST}:{TLS_PORT}")
    titles = {f.title for f in findings}
    assert "TLS certificate is self-signed" in titles


def test_tls_scanner_unreachable_port():
    result = TLSScanner(get_settings()).scan(HOST, 1)
    assert result.connected is False
    assert result.errors  # connection failure recorded
