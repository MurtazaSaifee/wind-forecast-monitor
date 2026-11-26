"""Per-IP sliding-window rate limiting on ``/api/*`` returns RFC 7807 429 problems."""

from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.core.rate_limit import RATE_LIMIT_EXCEEDED, RateLimitMiddleware
from app.core.request_context import RequestContextMiddleware
from app.core.security_headers import SECURITY_HEADERS, SecurityHeadersMiddleware


def _build_limited_app(
    *,
    max_requests: int = 3,
    window_seconds: float = 60.0,
    max_clients: int = 100,
    clock_box: list[float] | None = None,
    static_dir: Path | None = None,
) -> FastAPI:
    now_box = clock_box if clock_box is not None else [100.0]
    app = FastAPI()

    @app.get("/api/v1/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    if static_dir is not None:
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="frontend")

    app.add_middleware(
        RateLimitMiddleware,
        max_requests=max_requests,
        window_seconds=window_seconds,
        max_clients=max_clients,
        clock=lambda: now_box[0],
    )
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    return app


async def test_requests_within_limit_succeed_with_rate_limit_headers():
    app = _build_limited_app(max_requests=3)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.get("/api/v1/health")
        second = await client.get("/api/v1/health")

    assert first.status_code == 200
    assert first.headers["ratelimit-limit"] == "3"
    assert first.headers["ratelimit-remaining"] == "2"
    assert second.status_code == 200
    assert second.headers["ratelimit-remaining"] == "1"


async def test_exceeding_limit_returns_429_problem_with_security_and_retry_headers():
    app = _build_limited_app(max_requests=2, window_seconds=30.0)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await client.get("/api/v1/health")
        await client.get("/api/v1/health")
        blocked = await client.get("/api/v1/health")

    assert blocked.status_code == 429
    assert blocked.headers["content-type"] == "application/problem+json"
    assert blocked.headers["retry-after"] == "30"
    assert blocked.headers["ratelimit-remaining"] == "0"
    assert "cache-control" not in blocked.headers
    assert "x-request-id" in blocked.headers
    for name, value in SECURITY_HEADERS.items():
        assert blocked.headers[name.lower()] == value

    body = blocked.json()
    assert body == {
        "type": RATE_LIMIT_EXCEEDED,
        "title": "Too Many Requests",
        "status": 429,
        "detail": "Rate limit exceeded. Please retry later.",
        "instance": "/api/v1/health",
    }


async def test_distinct_client_ips_have_independent_buckets():
    app = _build_limited_app(max_requests=1)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        ip_a_1 = await client.get("/api/v1/health", headers={"X-Real-IP": "198.51.100.1"})
        ip_a_2 = await client.get("/api/v1/health", headers={"X-Real-IP": "198.51.100.1"})
        ip_b_1 = await client.get(
            "/api/v1/health",
            headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.1"},
        )

    assert ip_a_1.status_code == 200
    assert ip_a_2.status_code == 429
    assert ip_b_1.status_code == 200


async def test_bucket_recovers_after_window_elapses():
    clock = [100.0]
    app = _build_limited_app(max_requests=1, window_seconds=10.0, clock_box=clock)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.get("/api/v1/health")
        blocked = await client.get("/api/v1/health")
        clock[0] += 10.1
        recovered = await client.get("/api/v1/health")

    assert first.status_code == 200
    assert blocked.status_code == 429
    assert recovered.status_code == 200


async def test_static_frontend_routes_are_not_throttled(static_dir: Path):
    app = _build_limited_app(max_requests=1, static_dir=static_dir)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.get("/")
        second = await client.get("/")

    assert first.status_code == 200
    assert second.status_code == 200
    assert "ratelimit-limit" not in second.headers


async def test_evicts_oldest_clients_when_max_clients_is_reached():
    app = _build_limited_app(max_requests=1, max_clients=2)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await client.get("/api/v1/health", headers={"X-Real-IP": "192.0.2.1"})
        await client.get("/api/v1/health", headers={"X-Real-IP": "192.0.2.2"})
        third = await client.get("/api/v1/health", headers={"X-Real-IP": "192.0.2.3"})

    assert third.status_code == 200
