"""Simple in-memory sliding-window rate limiter.

Per-client-IP limits protect authentication and API endpoints from abuse.
In-memory is appropriate for a single-process lab deployment; production
deployments should use a shared store (e.g. Redis) behind the same interface.
"""

import threading
import time
from collections import defaultdict, deque
from typing import Callable

from fastapi import Depends, Request

from app.utils.errors import RateLimitError


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self._max = max_requests
        self._window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self._window:
                hits.popleft()
            if len(hits) >= self._max:
                return False
            hits.append(now)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


def make_rate_limit_dependency(
    max_requests: int, window_seconds: int
) -> Callable:
    """Build a FastAPI dependency enforcing a rate limit per client IP."""
    limiter = RateLimiter(max_requests, window_seconds)

    def dependency(request: Request) -> None:
        key = _client_key(request)
        if not limiter.allow(key):
            raise RateLimitError("Too many requests. Please try again later.")

    return dependency


def _client_key(request: Request) -> str:
    client = request.client
    if client is None:
        return "unknown"
    # Respect a single trusted proxy hop for deployments behind a reverse proxy.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return client.host


def _scope_client_key(scope) -> str:
    client = scope.get("client")
    if client and client[0]:
        return client[0]
    return "unknown"


class RateLimitMiddleware:
    """Pure-ASGI per-IP rate limiter for the API surface."""

    def __init__(self, app, max_requests: int, window_seconds: int, path_prefix: str = "/api"):
        self.app = app
        self._limiter = RateLimiter(max_requests, window_seconds)
        self._path_prefix = path_prefix

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") == "http" and scope.get("path", "").startswith(self._path_prefix):
            if not self._limiter.allow(_scope_client_key(scope)):
                body = (
                    '{"error": {"code": "rate_limited", "detail": '
                    '"Too many requests. Please try again later."}}'
                ).encode("utf-8")
                headers = [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"retry-after", b"60"),
                ]
                await send({"type": "http.response.start", "status": 429, "headers": headers})
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)
