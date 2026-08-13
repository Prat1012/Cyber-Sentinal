"""Nmap XML parsing tests (Phase 4 / 20)."""

from pathlib import Path

import pytest

from app.scanners.nmap_parser import parse_nmap_xml

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


def test_parse_sample_xml():
    hosts = parse_nmap_xml(FIXTURE.read_text(encoding="utf-8"))
    assert len(hosts) == 1  # only the "up" host is returned
    host = hosts[0]
    assert host.ip_address == "127.0.0.1"
    assert host.hostname == "localhost"
    assert host.os_guess == "Linux 5.x"
    assert len(host.ports) == 3

    by_port = {p.port: p for p in host.ports}
    ssh = by_port[22]
    assert ssh.state == "open"
    assert ssh.service == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "9.6p1"

    http = by_port[80]
    assert http.service == "http"
    assert http.product == "nginx"


def test_parse_invalid_xml_raises_value_error():
    with pytest.raises(ValueError):
        parse_nmap_xml("this is <<< not xml")


def test_parse_empty_hosts():
    assert parse_nmap_xml("<nmaprun></nmaprun>") == []
