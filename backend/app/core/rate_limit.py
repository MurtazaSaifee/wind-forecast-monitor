"""In-memory per-IP sliding-window rate limiter for ``/api/*`` routes, as a pure ASGI middleware."""

import math
import time
from collections import deque
from collections.abc import Callable

from fastapi.responses import JSONResponse
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.problems import PROBLEM_MEDIA_TYPE

RATE_LIMIT_EXCEEDED = "urn:wind-forecast:problem:rate-limit-exceeded"
DEFAULT_MAX_REQUESTS = 120
DEFAULT_WINDOW_SECONDS = 60.0
DEFAULT_MAX_CLIENTS = 10_000


def _client_ip(scope: Scope) -> str:
    headers = Headers(scope=scope)
    real_ip = headers.get("x-real-ip")
    if real_ip and real_ip.strip():
        return real_ip.strip()
    forwarded_for = headers.get("x-forwarded-for")
    if forwarded_for:
        first = forwarded_for.split(",", 1)[0].strip()
        if first:
            return first
    client = scope.get("client")
    if isinstance(client, tuple) and client and isinstance(client[0], str):
        return client[0]
    return "unknown"


class RateLimitMiddleware:
    """Limits ``/api/*`` requests per client IP using a bounded in-memory sliding window."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        max_clients: int = DEFAULT_MAX_CLIENTS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.app = app
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self._clock = clock
        self._buckets: dict[str, deque[float]] = {}

    def _prune_bucket(self, bucket: deque[float], cutoff: float) -> None:
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

    def _evict_if_full(self, cutoff: float) -> None:
        if len(self._buckets) < self.max_clients:
            return
        stale_keys = [
            key for key, bucket in self._buckets.items() if not bucket or bucket[-1] <= cutoff
        ]
        for key in stale_keys:
            del self._buckets[key]
        while len(self._buckets) >= self.max_clients:
            oldest_key = next(iter(self._buckets))
            del self._buckets[oldest_key]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        if path != "/api" and not path.startswith("/api/"):
            await self.app(scope, receive, send)
            return

        now = self._clock()
        cutoff = now - self.window_seconds
        ip = _client_ip(scope)

        bucket = self._buckets.get(ip)
        if bucket is None:
            self._evict_if_full(cutoff)
            new_bucket: deque[float] = deque()
            self._buckets[ip] = new_bucket
            bucket = new_bucket
        else:
            self._prune_bucket(bucket, cutoff)
            # Refresh insertion order so active IPs are kept over idle ones on eviction.
            self._buckets[ip] = self._buckets.pop(ip)

        if len(bucket) >= self.max_requests:
            retry_after = max(1, math.ceil(bucket[0] + self.window_seconds - now))
            rate_headers = {
                "Retry-After": str(retry_after),
                "RateLimit-Limit": str(self.max_requests),
                "RateLimit-Remaining": "0",
                "RateLimit-Reset": str(retry_after),
            }
            response = JSONResponse(
                status_code=429,
                content={
                    "type": RATE_LIMIT_EXCEEDED,
                    "title": "Too Many Requests",
                    "status": 429,
                    "detail": "Rate limit exceeded. Please retry later.",
                    "instance": path,
                },
                media_type=PROBLEM_MEDIA_TYPE,
                headers=rate_headers,
            )
            await response(scope, receive, send)
            return

        bucket.append(now)
        remaining = max(0, self.max_requests - len(bucket))
        reset = max(1, math.ceil(bucket[0] + self.window_seconds - now))
        rate_header_bytes = [
            (b"ratelimit-limit", str(self.max_requests).encode("latin-1")),
            (b"ratelimit-remaining", str(remaining).encode("latin-1")),
            (b"ratelimit-reset", str(reset).encode("latin-1")),
        ]

        async def send_with_rate_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = [*message.get("headers", []), *rate_header_bytes]
            await send(message)

        await self.app(scope, receive, send_with_rate_headers)
