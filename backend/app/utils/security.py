"""Password hashing and JWT helpers.

Passwords are hashed with bcrypt (never stored in plaintext). Sessions use
signed JWT access tokens. This module is intentionally framework-agnostic so
the authentication approach can be swapped without touching the API layer.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt

from app.config import get_settings


def hash_password(password: str) -> str:
    """Return a bcrypt hash of the password."""
    rounds = get_settings().BCRYPT_ROUNDS
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=rounds)).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(subject: str, expires_minutes: int | None = None) -> tuple[str, int]:
    """Create a signed JWT. Returns (token, expires_in_seconds)."""
    settings = get_settings()
    ttl = expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=ttl),
        "iss": settings.APP_NAME,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, ttl * 60


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT. Raises jwt.PyJWTError on failure."""
    settings = get_settings()
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
