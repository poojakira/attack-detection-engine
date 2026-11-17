"""Bound actual ASGI input before JSON parsing; one total receive deadline."""

from __future__ import annotations

import anyio
from starlette.responses import JSONResponse


class BodyLimitMiddleware:
    def __init__(self, app, *, max_bytes: int, timeout: float = 15):
        self.app = app
        self.max_bytes = max_bytes
        self.timeout = timeout

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks = []
        received = 0
        try:
            with anyio.fail_after(self.timeout):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    received += len(chunk)
                    if received > self.max_bytes:
                        return await JSONResponse(
                            {"detail": "request body too large"}, 413
                        )(scope, receive, send)
                    chunks.append(chunk)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            return await JSONResponse(
                {"detail": "request body receive timed out"}, 408
            )(scope, receive, send)
        body = b"".join(chunks)
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, send)
