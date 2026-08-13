"""Parse Nmap XML output into structured HostData objects.

Uses only the standard library ``xml.etree.ElementTree``. The input is output
produced by our own subprocess invocation of nmap (trusted), but parsing is
defensive: malformed or unexpected elements are skipped rather than raised.
"""

import logging
import xml.etree.ElementTree as ET

from app.scanners.base import HostData, PortData

logger = logging.getLogger(__name__)


def parse_nmap_xml(xml_text: str) -> list[HostData]:
    """Parse an nmap ``-oX`` document into a list of HostData."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.error("Failed to parse nmap XML: %s", exc)
        raise ValueError(f"Invalid nmap XML output: {exc}") from exc

    hosts: list[HostData] = []
    for host_el in root.iter("host"):
        host = _parse_host(host_el)
        if host is not None:
            hosts.append(host)
    return hosts


def _parse_host(host_el: ET.Element) -> HostData | None:
    status_el = host_el.find("status")
    status = (status_el.get("state") if status_el is not None else None) or "up"
    if status != "up":
        return None

    addresses = host_el.findall("address")
    ipv4 = None
    ipv6 = None
    mac = None
    for addr in addresses:
        addr_type = addr.get("addrtype", "")
        if addr_type == "ipv4":
            ipv4 = addr.get("addr")
        elif addr_type == "ipv6":
            ipv6 = addr.get("addr")
        elif addr_type == "mac":
            mac = addr.get("addr")
    ip_address = ipv4 or ipv6
    if not ip_address:
        logger.warning("Skipping nmap host without IP address")
        return None

    hostname = None
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        for hn in hostnames_el.findall("hostname"):
            name = hn.get("name")
            if name:
                hostname = name
                break

    os_guess = None
    os_el = host_el.find("os")
    if os_el is not None:
        for osmatch in os_el.findall("osmatch"):
            name = osmatch.get("name")
            if name:
                os_guess = name
                break

    ports: list[PortData] = []
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            port_data = _parse_port(port_el)
            if port_data is not None:
                ports.append(port_data)

    return HostData(
        ip_address=ip_address,
        hostname=hostname,
        status=status,
        os_guess=os_guess,
        mac_address=mac,
        ports=ports,
    )


def _parse_port(port_el: ET.Element) -> PortData | None:
    port = port_el.get("portid")
    protocol = port_el.get("protocol", "tcp")
    if not port or not port.isdigit():
        return None

    state_el = port_el.find("state")
    state = (state_el.get("state") if state_el is not None else None) or "unknown"

    service_el = port_el.find("service")
    name = product = version = None
    if service_el is not None:
        name = service_el.get("name")
        product = service_el.get("product")
        version = service_el.get("version")

    return PortData(
        port=int(port),
        protocol=protocol,
        state=state,
        service=name,
        product=product,
        version=version,
    )
