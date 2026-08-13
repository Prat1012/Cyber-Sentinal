"""Built-in TCP connect port scanner.

Used automatically when the nmap binary is unavailable so the platform remains
functional for authorized local lab testing. It is a plain, slow, rate-limited
``connect()`` probe with a bounded port count — no evasion, no flooding.

The engine name recorded for scans using this scanner is ``basic`` so results
are transparent about how they were produced.
"""

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.config import Settings
from app.scanners.base import HostData, PortData
from app.utils.errors import ValidationFailedError
from app.utils.validation import validate_port_range

logger = logging.getLogger(__name__)

# Common ports used for the "top-100" profile (mirrors well-known services).
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 514, 587,
    636, 873, 993, 995, 1025, 1080, 1433, 1521, 1723, 2049, 2375, 2376, 3000,
    3128, 3306, 3389, 4443, 5000, 5432, 5900, 5984, 5985, 6000, 6379, 7001,
    8000, 8008, 8009, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200, 9300,
    10000, 11211, 27017, 50000,
]

TOP_1000_PORTS = list(range(1, 1025))  # well-known + registered range

# Common development/lab ports whose service names are not always present in
# the OS services database (e.g. ``socket.getservbyport`` on Windows).
_SERVICE_FALLBACK = {
    80: "http",
    443: "https",
    3000: "http",
    5000: "http",
    8000: "http",
    8008: "http",
    8080: "http",
    8081: "http",
    8088: "http",
    8443: "https",
    8888: "http",
    9000: "http",
    9090: "http",
    18080: "http",
}


class FallbackPortScanner:
    """Rate-limited TCP connect scanner used when nmap is unavailable."""

    ENGINE_NAME = "basic"

    def __init__(self, settings: Settings):
        self._settings = settings

    def available(self) -> bool:
        return True

    def scan(
        self,
        target: str,
        port_range: str = "top-1000",
        timeout_seconds: float = 1.5,
        max_workers: int = 40,
    ) -> list[HostData]:
        port_range = validate_port_range(port_range)
        ports = self._ports_for(port_range)

        if target in ("localhost", "localhost.localdomain"):
            host = "127.0.0.1"
        else:
            host = target

        open_ports: list[PortData] = []
        logger.info("Fallback TCP scan host=%s ports=%s", host, len(ports))

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_map = {
                pool.submit(self._probe, host, port, timeout_seconds): port
                for port in ports
            }
            for future in as_completed(future_map):
                port = future_map[future]
                try:
                    service = future.result()  # str service name, "" if open but unknown, None if closed
                except Exception:  # pragma: no cover - defensive
                    service = None
                if service is not None:
                    open_ports.append(
                        PortData(port=port, state="open", service=service or None)
                    )

        open_ports.sort(key=lambda p: p.port)
        return [
            HostData(
                ip_address=host,
                status="up",
                is_local=True,
                ports=open_ports,
            )
        ]

    def _ports_for(self, port_range: str) -> list[int]:
        if port_range == "top-100":
            return TOP_100_PORTS
        if port_range == "top-1000":
            return TOP_1000_PORTS
        start_s, _, end_s = port_range.partition("-")
        start, end = int(start_s), int(end_s or start_s)
        return list(range(start, end + 1))

    def _probe(self, host: str, port: int, timeout: float) -> str | None:
        """Return the service name for an open port.

        Returns an empty string when the port is open but the service name is
        unknown (so the caller records the port), and None when closed.
        """
        try:
            with socket.create_connection((host, port), timeout=timeout):
                try:
                    return socket.getservbyport(port, "tcp")
                except OSError:
                    return _SERVICE_FALLBACK.get(port, "")
        except (OSError, socket.timeout):
            return None
