"""CyberSentinel local lab target.

Starts a small HTTP server on 127.0.0.1 that intentionally mimics common
insecure configurations so the platform can be exercised end-to-end against an
explicitly authorized, self-owned lab target:

- Missing security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options)
- Cookies without Secure / HttpOnly / SameSite
- Server banner disclosing software + version
- Sensitive-looking paths (/admin, /backup.zip, /.git/config)

Usage:  python scripts/local_lab.py [--port 8080]
This binds to 127.0.0.1 only. Never expose it to a network.
"""

import argparse
import http.server
import socket
import socketserver

BANNER = "local-lab/1.0 (Python/3.13)"


class LabHandler(http.server.BaseHTTPRequestHandler):
    # The Server banner intentionally discloses software + version so the
    # scanner has real evidence for information-disclosure findings.
    server_version = "local-lab/1.0"
    sys_version = "(Python/3.13)"

    def log_message(self, fmt, *args):
        print(f"[local-lab] {self.address_string()} {fmt % args}")

    def _send(self, status: int, body: bytes, content_type: str = "text/html", extra_headers=None):
        self.send_response(status)
        # Intentionally omit security headers (this is the point of the lab).
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/":
            # Cookie without Secure / HttpOnly / SameSite (intentional lab flaw).
            self._send(
                200,
                b"<html><head><title>Local Lab</title></head>"
                b"<body><h1>Welcome to the CyberSentinel local lab</h1>"
                b"<p>This lab intentionally omits security headers.</p></body></html>",
                extra_headers={"Set-Cookie": "session=abc123; Path=/"},
            )
        elif path == "/admin":
            self._send(200, b"<html><body><h1>Admin console</h1>"
                            b"<p>This path should not be public.</p></body></html>")
        elif path == "/backup.zip":
            self._send(200, b"PK\x03\x04FAKEBACKUP", "application/zip")
        elif path == "/.git/config":
            self._send(200, b"[core]\n\trepositoryformatversion = 0\n"
                            b"\tbare = false\n\turl = https://example.com/repo.git\n")
        elif path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /admin\n", "text/plain")
        elif path == "/api/info":
            self._send(200, b'{"service": "local-lab", "version": "1.0"}', "application/json")
        elif path == "/login":
            # Cookie without Secure / HttpOnly / SameSite (intentional lab flaw).
            self._send(
                200,
                b"<html><body><h1>Login</h1></body></html>",
                extra_headers={"Set-Cookie": "session=abc123; Path=/"},
            )
        else:
            self._send(404, b"<html><body><h1>Not found</h1></body></html>")


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberSentinel local lab target")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    if args.port < 1 or args.port > 65535:
        raise SystemExit("Invalid port.")

    server = ThreadingHTTPServer(("127.0.0.1", args.port), LabHandler)
    print(f"[local-lab] listening on http://127.0.0.1:{args.port} (loopback only)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[local-lab] shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
