"""Security response headers middleware.

The application itself is a web application and must ship secure defaults:
hardened headers on every response, and a neutral Server banner. Note that the
CSP below is intentionally scoped to the frontend (self + jsdelivr for
Chart.js); API JSON responses are unaffected.
"""

import logging

from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; form-action 'self'; "
        "frame-ancestors 'none'"
    ),
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            if header not in response.headers:
                response.headers[header] = value
        response.headers["Server"] = "CyberSentinel"
        return response
