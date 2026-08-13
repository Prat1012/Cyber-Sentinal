"""Database engine, session factory and declarative base.

SQLite is used for development; a PostgreSQL DSN can be supplied via
``DATABASE_URL`` for production (SQLAlchemy handles both).
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import get_settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


settings = get_settings()
_is_sqlite = settings.DATABASE_URL.startswith("sqlite")
# In-memory SQLite (used by the test suite) shares one connection via StaticPool.
_is_memory = _is_sqlite and ":memory:" in settings.DATABASE_URL

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if _is_sqlite else {},
    poolclass=StaticPool if _is_memory else None,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def get_db():
    """FastAPI dependency yielding a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create tables if they do not exist (development convenience).

    Production deployments should use ``alembic upgrade head`` instead.
    """
    from app import models  # noqa: F401  (register all models)

    Base.metadata.create_all(bind=engine)
