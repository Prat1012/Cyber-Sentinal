"""Logging configuration with secret redaction.

Never log tokens, passwords or secret material. A ``RedactingFilter`` scrubs
known secret values and Authorization headers from every log record.
"""

import logging
import sys
from typing import Iterable

from app.config import get_settings


class RedactingFilter(logging.Filter):
    """Redact configured secrets and bearer tokens from log messages."""

    def __init__(self, secrets: Iterable[str]):
        super().__init__()
        self._secrets = [s for s in secrets if s and s != "dev-only-insecure-secret-key-change-me"]

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        redacted = msg
        for secret in self._secrets:
            if secret and secret in redacted:
                redacted = redacted.replace(secret, "[REDACTED]")
        redacted = _redact_bearer(redacted)
        if redacted != msg:
            record.msg = redacted
            record.args = ()
        return True


def _redact_bearer(text: str) -> str:
    import re

    return re.sub(r"(?i)(authorization:\s*bearer\s+)\S+", r"\1[REDACTED]", text)


def setup_logging(level: str | None = None, log_file: str = "") -> None:
    """Configure root logging with a redaction filter."""
    settings = get_settings()
    log_level = (level or settings.LOG_LEVEL or "INFO").upper()

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        handlers=handlers,
        force=True,
    )

    secret_values = [
        settings.SECRET_KEY,
        settings.DATABASE_URL.split("://")[-1].split("@")[-1] if "@" in settings.DATABASE_URL else "",
    ]
    redactor = RedactingFilter(secret_values)
    for handler in handlers:
        handler.addFilter(redactor)
