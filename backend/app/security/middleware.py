"""Request body size limiting (pure ASGI middleware).

Streams request bodies and rejects oversized payloads with HTTP 413 before
they reach application code. Implemented as plain ASGI (not BaseHTTPMiddleware)
so the request body can be safely replayed to downstream handlers.
"""

import json
import logging

from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)

_BODY_METHODS = {"POST", "PUT", "PATCH"}


class RequestSizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int = 1_000_000):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in _BODY_METHODS:
            await self.app(scope, receive, send)
            return

        # Fast path: reject based on the Content-Length header.
        content_length = _header_value(scope, b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.max_bytes:
                    await self._send_413(send)
                    return
            except ValueError:
                pass

        body, too_large = await self._read_body(receive)
        if too_large:
            await self._send_413(send)
            return

        messages: list[Message] = [
            {"type": "http.request", "body": body, "more_body": False}
        ]

        async def replay_receive() -> Message:
            if messages:
                return messages.pop(0)
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)

    async def _read_body(self, receive: Receive) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            chunk = message.get("body", b"") or b""
            chunks.append(chunk)
            size += len(chunk)
            if size > self.max_bytes:
                return b"", True
            if not message.get("more_body"):
                break
        return b"".join(chunks), False

    async def _send_413(self, send: Send) -> None:
        body = json.dumps(
            {
                "error": {
                    "code": "payload_too_large",
                    "detail": f"Request body exceeds the {self.max_bytes} byte limit.",
                }
            }
        ).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ]
        await send({"type": "http.response.start", "status": 413, "headers": headers})
        await send({"type": "http.response.body", "body": body})


def _header_value(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers") or []:
        if key.lower() == name:
            return value.decode("latin-1")
    return None
