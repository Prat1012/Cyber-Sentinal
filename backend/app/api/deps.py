"""Shared FastAPI dependencies (authentication)."""

import logging
from typing import Optional

import jwt as pyjwt
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models.user import User
from app.utils.errors import AuthError
from app.utils.security import decode_access_token

logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    db: Session = Depends(get_db),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> User:
    """Resolve the authenticated user from the Bearer token.

    When ``AUTH_ENABLED=false`` a single shared ``local`` account is used so the
    platform remains usable for single-user lab deployments.
    """
    settings = get_settings()
    if not settings.AUTH_ENABLED:
        return _get_or_create_local_user(db)

    if credentials is None:
        raise AuthError("Not authenticated. Provide a Bearer token.")

    try:
        payload = decode_access_token(credentials.credentials)
        subject = payload.get("sub")
        if subject is None:
            raise AuthError("Invalid token payload.")
        user = db.get(User, int(subject))
    except (pyjwt.PyJWTError, ValueError, TypeError):
        raise AuthError("Invalid or expired token.") from None

    if user is None or not user.is_active:
        raise AuthError("Invalid or expired token.")
    return user


def _get_or_create_local_user(db: Session) -> User:
    user = db.scalar(select(User).where(User.username == "local"))
    if user is None:
        user = User(username="local", hashed_password="!")
        db.add(user)
        db.commit()
        db.refresh(user)
    return user
