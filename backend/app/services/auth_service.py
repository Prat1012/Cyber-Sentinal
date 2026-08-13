"""Authentication service: registration, login, token issuance."""

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse
from app.utils.errors import AuthError, ConflictError, ValidationFailedError
from app.utils.security import create_access_token, hash_password, verify_password
from app.utils.validation import validate_password, validate_username

logger = logging.getLogger(__name__)


def register_user(db: Session, data: RegisterRequest) -> User:
    validate_username(data.username)
    validate_password(data.password)

    exists = db.scalar(select(User).where(User.username == data.username))
    if exists:
        raise ConflictError("Username is already taken.")
    if data.email:
        email_exists = db.scalar(select(User).where(User.email == data.email))
        if email_exists:
            raise ConflictError("Email is already registered.")

    user = User(
        username=data.username,
        email=data.email,
        hashed_password=hash_password(data.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("Registered user id=%s", user.id)
    return user


def authenticate_user(db: Session, data: LoginRequest) -> User:
    user = db.scalar(select(User).where(User.username == data.username))
    # Constant-ish behavior: always perform a hash comparison to reduce
    # user-enumeration timing differences for non-existent accounts.
    dummy_hash = hash_password("dummy-password-for-timing")
    if user is None or not user.is_active:
        verify_password(data.password, dummy_hash)
        raise AuthError("Invalid username or password.")
    if not verify_password(data.password, user.hashed_password):
        raise AuthError("Invalid username or password.")
    return user


def issue_token(user: User) -> TokenResponse:
    token, expires_in = create_access_token(str(user.id))
    return TokenResponse(access_token=token, expires_in=expires_in)


def get_user_or_404(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise ValidationFailedError("Account not found or disabled.")
    return user
