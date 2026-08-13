"""Controlled directory discovery.

Uses a small configurable wordlist, enforces per-request delays (rate
limiting), a request timeout, a hard maximum number of paths, and never
recurses. No credential brute-forcing.
"""

import logging
import time
from typing import Optional

import requests

from app.config import Settings
from app.scanners.base import DirEntry
from app.scanners.web_scanner import USER_AGENT

logger = logging.getLogger(__name__)


class DirectoryScanner:
    """Probe a fixed wordlist of paths on an authorized web target."""

    def __init__(self, settings: Settings):
        self._settings = settings

    def scan(
        self,
        base_url: str,
        wordlist: Optional[list[str]] = None,
        max_paths: Optional[int] = None,
        delay_seconds: Optional[float] = None,
    ) -> list[DirEntry]:
        paths = wordlist if wordlist is not None else self._settings.directory_wordlist
        max_paths = max_paths if max_paths is not None else self._settings.DIRECTORY_MAX_PATHS
        delay = delay_seconds if delay_seconds is not None else self._settings.DIRECTORY_DELAY_SECONDS

        paths = paths[:max_paths]
        if not paths or max_paths <= 0:
            return []

        base = base_url.rstrip("/")
        timeout = (self._settings.WEB_CONNECT_TIMEOUT, self._settings.WEB_READ_TIMEOUT)
        found: list[DirEntry] = []

        for path in paths:
            url = f"{base}/{path.lstrip('/')}"
            try:
                resp = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=False,
                    headers={"User-Agent": USER_AGENT},
                )
            except requests.RequestException:
                time.sleep(delay)
                continue

            if resp.status_code < 400 or resp.status_code in (403, 401, 405):
                found.append(
                    DirEntry(
                        url=url,
                        status_code=resp.status_code,
                        content_length=len(resp.content),
                        content_type=resp.headers.get("content-type", ""),
                    )
                )
            resp.close()
            time.sleep(delay)

        found.sort(key=lambda e: e.status_code)
        logger.info("Directory discovery on %s found %s entries", base, len(found))
        return found
