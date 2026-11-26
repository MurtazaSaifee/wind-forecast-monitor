"""Security headers on every response, from a pure ASGI middleware.

The Vercel deployment sets the same headers in vercel.json. This middleware covers the Docker image.
The unexpected-error answer is sent outside the middleware stack, so it sets them itself.
"""

from starlette.types import ASGIApp, Message, Receive, Scope, Send

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
}

_RAW_SECURITY_HEADERS = [
    (name.lower().encode("latin-1"), value.encode("latin-1"))
    for name, value in SECURITY_HEADERS.items()
]


class SecurityHeadersMiddleware:
    """Adds the security headers to every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = [*message.get("headers", []), *_RAW_SECURITY_HEADERS]
            await send(message)

        await self.app(scope, receive, send_with_security_headers)
