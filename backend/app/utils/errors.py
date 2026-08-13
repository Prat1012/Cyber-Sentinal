"""Application exception types and global error handling.

Error responses never leak stack traces or internal state to clients in
production; server-side details are only written to the log.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)


class AppError(Exception):
    """Base class for expected application errors."""

    status_code = 500
    code = "internal_error"

    def __init__(self, detail: str, *, code: str | None = None):
        super().__init__(detail)
        self.detail = detail
        if code:
            self.code = code


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"


class ValidationFailedError(AppError):
    status_code = 400
    code = "validation_error"


class AuthError(AppError):
    status_code = 401
    code = "unauthorized"


class ForbiddenError(AppError):
    status_code = 403
    code = "forbidden"


class ConflictError(AppError):
    status_code = 409
    code = "conflict"


class RateLimitError(AppError):
    status_code = 429
    code = "rate_limited"


class ScannerUnavailableError(AppError):
    status_code = 503
    code = "scanner_unavailable"


class ScanAuthorizationError(ForbiddenError):
    """Raised when a target is outside the authorized scope policy."""


def error_response(status_code: int, code: str, detail: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "detail": detail}},
        headers=headers,
    )


def register_exception_handlers(app: FastAPI, debug: bool = False) -> None:
    @app.exception_handler(AppError)
    async def app_error_handler(_: Request, exc: AppError):
        if exc.status_code >= 500:
            logger.error("AppError %s: %s", exc.code, exc.detail)
        else:
            logger.warning("AppError %s: %s", exc.code, exc.detail)
        headers = {"Retry-After": "60"} if exc.status_code == 429 else None
        return error_response(exc.status_code, exc.code, exc.detail, headers=headers)

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(_: Request, exc: StarletteHTTPException):
        # Map standard HTTP exceptions into the same error envelope.
        code = "http_error"
        if exc.status_code == 401:
            code = "unauthorized"
        elif exc.status_code == 403:
            code = "forbidden"
        elif exc.status_code == 404:
            code = "not_found"
        elif exc.status_code == 405:
            code = "method_not_allowed"
        return error_response(exc.status_code, code, str(exc.detail))

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(_: Request, exc: Exception):
        # Never leak internals to the client.
        logger.exception("Unhandled exception: %s", type(exc).__name__)
        detail = str(exc) if debug else "An unexpected error occurred."
        return error_response(500, "internal_error", detail)
