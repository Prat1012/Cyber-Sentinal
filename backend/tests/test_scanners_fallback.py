"""Fallback TCP connect scanner tests + nmap availability handling."""

from app.config import get_settings
from app.scanners.fallback_scanner import FallbackPortScanner
from app.scanners.nmap_scanner import NmapScanner
from tests.lab_server import HTTP_PORT, LabHTTPServer


def test_fallback_scanner_finds_open_lab_port(lab_server):
    scanner = FallbackPortScanner(get_settings())
    hosts = scanner.scan("127.0.0.1", port_range=f"{HTTP_PORT}-{HTTP_PORT}")
    assert len(hosts) == 1
    assert hosts[0].ip_address == "127.0.0.1"
    assert hosts[0].ports
    assert hosts[0].ports[0].port == HTTP_PORT
    assert hosts[0].ports[0].state == "open"


def test_fallback_scanner_ignores_closed_ports():
    scanner = FallbackPortScanner(get_settings())
    hosts = scanner.scan("127.0.0.1", port_range="1-10")
    # Local closed ports produce no open results.
    assert all(p.state != "open" for p in hosts[0].ports) or not hosts[0].ports


def test_nmap_unavailable_when_binary_missing():
    settings = get_settings()
    settings.NMAP_BIN_PATH = "definitely-not-a-real-nmap-binary"
    scanner = NmapScanner(settings)
    assert scanner.available() is False
    # Restore for other tests.
    settings.NMAP_BIN_PATH = "nmap"
