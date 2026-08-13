"""CyberSentinel FastAPI application.

Run from the ``backend/`` directory:

    uvicorn app.main:app --reload

The API is served under ``/api`` and the frontend is mounted at ``/``.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api import auth, dashboard, findings, reports, scans, targets
from app.config import get_settings
from app.database import init_db
from app.jobs import job_manager
from app.security.headers import SecurityHeadersMiddleware
from app.security.middleware import RequestSizeLimitMiddleware
from app.security.rate_limit import RateLimitMiddleware
from app.utils.errors import register_exception_handlers
from app.utils.logging import setup_logging

logger = logging.getLogger(__name__)
settings = get_settings()


# Create tables at import time for development convenience (SQLite).
# Production deployments should use ``alembic upgrade head`` instead.
if settings.AUTO_CREATE_TABLES:
    init_db()


@asynccontextmanager
async def lifespan(_: FastAPI):
    setup_logging()
    logger.info("Starting %s v%s (%s)", settings.APP_NAME, settings.APP_VERSION, settings.APP_ENV)
    job_manager.start()
    try:
        yield
    finally:
        job_manager.shutdown()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Automated Vulnerability Assessment & Security Reporting Platform. "
        "Authorized use only - assess only systems you own or have explicit "
        "permission to test."
    ),
    docs_url="/api/docs",
    redoc_url=None,
    lifespan=lifespan,
)

# Middleware order: last added runs first (outermost).
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=1_000_000)
app.add_middleware(
    RateLimitMiddleware,
    max_requests=settings.RATE_LIMIT_REQUESTS,
    window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

register_exception_handlers(app, debug=settings.DEBUG)


@app.get("/api/health", tags=["health"])
def health() -> dict:
    return {"status": "ok"}


app.include_router(auth.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(dashboard.router)

# Mount the frontend (must be last so /api routes take precedence).
if settings.frontend_path.is_dir():
    app.mount(
        "/",
        StaticFiles(directory=str(settings.frontend_path), html=True),
        name="frontend",
    )
    logger.info("Frontend mounted from %s", settings.frontend_path)
else:
    logger.warning("Frontend directory %s not found; serving API only.", settings.frontend_path)
