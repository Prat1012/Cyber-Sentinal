"""Web technology detection and header collection.

Uses ``requests`` with strict timeouts and a maximum response size. Response
bodies are read as a stream and truncated; returned content is never executed
or stored in full.
"""

import logging
from typing import Optional

import requests

from app.config import Settings
from app.scanners.base import WebResult

logger = logging.getLogger(__name__)

USER_AGENT = "CyberSentinel/1.0 (authorized security assessment)"

# Header -> technology fingerprints (case-insensitive substring matching).
_TECH_SIGNATURES: list[tuple[str, tuple[str, ...]]] = [
    ("nginx", ("nginx",)),
    ("Apache HTTP Server", ("apache",)),
    ("Microsoft IIS", ("microsoft-iis", "iis/")),
    ("Cloudflare", ("cloudflare",)),
    ("Express (Node.js)", ("express",)),
    ("Python", ("python",)),
    ("PHP", ("php/",)),
    ("Netlify", ("netlify",)),
    ("Vercel", ("vercel",)),
    ("GitHub Pages", ("github",)),
    ("WordPress", ("wordpress",)),
    ("Traefik", ("traefik",)),
    ("Caddy", ("caddy",)),
    ("lighttpd", ("lighttpd",)),
]


class WebScanner:
    """Collects HTTP metadata for an authorized web target."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._session = requests.Session()
        self._session.max_redirects = 5

    def scan(self, url: str) -> Optional[WebResult]:
        connect_timeout = self._settings.WEB_CONNECT_TIMEOUT
        read_timeout = self._settings.WEB_READ_TIMEOUT
        max_bytes = self._settings.WEB_MAX_RESPONSE_BYTES

        try:
            resp = self._session.get(
                url,
                timeout=(connect_timeout, read_timeout),
                allow_redirects=True,
                stream=True,
                headers={"User-Agent": USER_AGENT},
            )
        except requests.RequestException as exc:
            logger.info("Web request failed for %s: %s", url, exc)
            return None

        # Read a bounded amount of the body, then discard the connection.
        content_length = 0
        try:
            for chunk in resp.iter_content(chunk_size=8192):
                content_length += len(chunk)
                if content_length >= max_bytes:
                    resp.close()
                    content_length = max_bytes
                    break
        except requests.RequestException:
            resp.close()
            return None
        finally:
            resp.close()

        headers = {k.lower(): v for k, v in resp.headers.items()}
        redirect_chain = [r.url for r in resp.history]

        return WebResult(
            url=url,
            status_code=resp.status_code,
            headers=headers,
            final_url=resp.url,
            redirect_chain=redirect_chain,
            cookies=self._extract_cookies(resp.cookies),
            technologies=self._detect_technologies(headers),
            content_length=content_length,
            content_type=resp.headers.get("content-type", ""),
        )

    @staticmethod
    def _extract_cookies(cookies) -> list[dict]:
        """Normalize http.cookiejar cookies (HttpOnly/SameSite live in ``rest``)."""
        out: list[dict] = []
        for c in cookies:
            rest = getattr(c, "rest", None) or {}
            flags = {
                "secure": bool(getattr(c, "secure", False)),
                "httponly": bool(
                    rest.get("HttpOnly") or getattr(c, "httponly", False)
                ),
                "samesite": (rest.get("SameSite") or getattr(c, "samesite", "") or ""),
            }
            out.append({"name": getattr(c, "name", "?"), "value": getattr(c, "value", ""), "flags": flags})
        return out

    @staticmethod
    def _detect_technologies(headers: dict[str, str]) -> list[str]:
        techs: list[str] = []
        blob = " ".join(
            headers.get(h, "")
            for h in ("server", "x-powered-by", "via", "x-generator")
        ).lower()
        for name, needles in _TECH_SIGNATURES:
            if any(needle in blob for needle in needles):
                techs.append(name)
        return sorted(set(techs))
