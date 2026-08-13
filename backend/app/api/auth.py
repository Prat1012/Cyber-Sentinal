"""Authentication endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.config import get_settings
from app.database import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserOut
from app.security.rate_limit import make_rate_limit_dependency
from app.services import auth_service

router = APIRouter(prefix="/api/auth", tags=["auth"])

settings = get_settings()
login_limiter = make_rate_limit_dependency(
    settings.AUTH_RATE_LIMIT_REQUESTS, settings.AUTH_RATE_LIMIT_WINDOW_SECONDS
)
register_limiter = make_rate_limit_dependency(
    settings.AUTH_RATE_LIMIT_REQUESTS, settings.AUTH_RATE_LIMIT_WINDOW_SECONDS
)


@router.post("/register", response_model=UserOut, status_code=201)
def register(
    data: RegisterRequest,
    db: Session = Depends(get_db),
    _: None = Depends(register_limiter),
) -> User:
    return auth_service.register_user(db, data)


@router.post("/login", response_model=TokenResponse)
def login(
    data: LoginRequest,
    db: Session = Depends(get_db),
    _: None = Depends(login_limiter),
) -> TokenResponse:
    user = auth_service.authenticate_user(db, data)
    return auth_service.issue_token(user)


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user
