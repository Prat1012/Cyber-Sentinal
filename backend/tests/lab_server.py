"""Local lab HTTP and TLS servers used by scanner tests.

Binds to 127.0.0.1 only. The HTTP handler intentionally omits security headers,
discloses a banner and sets an insecure cookie so checks have real evidence.
"""

import http.server
import ipaddress
import socket
import socketserver
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HTTP_PORT = 18080
TLS_PORT = 18443

BANNER = "local-lab/1.0 (Python/3.13)"


class LabHandler(http.server.BaseHTTPRequestHandler):
    server_version = "local-lab/1.0"
    sys_version = "(Python/3.13)"

    def log_message(self, fmt, *args):  # silence test output
        pass

    def _send(self, status, body, content_type="text/html", extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/":
            self._send(
                200,
                b"<html><body><h1>Local Lab</h1></body></html>",
                extra_headers={"Set-Cookie": "session=abc123; Path=/"},
            )
        elif path == "/admin":
            self._send(200, b"<html><body>Admin</body></html>")
        elif path == "/.git/config":
            self._send(200, b"[core]\n\turl = https://example.com/repo.git\n")
        elif path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /admin\n", "text/plain")
        else:
            self._send(404, b"<html><body>Not found</body></html>")


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class LabHTTPServer:
    """Context manager running the lab HTTP server on 127.0.0.1:18080."""

    def __init__(self, port: int = HTTP_PORT):
        self.port = port
        self._server: _ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "LabHTTPServer":
        self._server = _ThreadingHTTPServer(("127.0.0.1", self.port), LabHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()


class LabTLSServer:
    """Context manager running an HTTPS server with a self-signed certificate."""

    def __init__(self, port: int = TLS_PORT):
        self.port = port
        self._server = None
        self._thread = None

    def __enter__(self) -> "LabTLSServer":
        cert_file, key_file = _make_self_signed_cert("127.0.0.1")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        self._server = _ThreadingHTTPServer(("127.0.0.1", self.port), LabHandler)
        self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()


def _make_self_signed_cert(hostname: str, days: int = 30) -> tuple[Path, Path]:
    """Generate a self-signed certificate valid for 127.0.0.1 (for lab use)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(hostname))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_file = Path(__file__).parent / f"lab_cert_{hostname.replace('.', '_')}.pem"
    key_file = Path(__file__).parent / f"lab_key_{hostname.replace('.', '_')}.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file
