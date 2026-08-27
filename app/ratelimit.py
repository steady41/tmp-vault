"""Per-IP fixed-window rate limiting for secret creation."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request

from .config import Settings


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    limit: int
    remaining: int


async def enforce_create_rate_limit(request: Request) -> RateLimitResult:
    """Enforce a fixed 60-second window per client IP, tracked in Redis.

    Raises ``HTTPException(429)`` when the limit is exceeded.
    """
    settings: Settings = request.app.state.settings
    redis = request.app.state.redis
    ip = _client_ip(request, settings)
    key = f"rl:create:{ip}"

    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 60)

    limit = settings.create_rate_limit_per_minute
    if count > limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")
    return RateLimitResult(limit=limit, remaining=max(limit - count, 0))


def _client_ip(request: Request, settings: Settings) -> str:
    """Resolve the client IP, optionally trusting ``X-Forwarded-For``.

    When ``VAULT_TRUST_PROXY`` is true the left-most entry of
    ``X-Forwarded-For`` is trusted — only enable this behind a trusted
    reverse proxy that strips external values.
    """
    if settings.trust_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # XFF may be "client, proxy1, proxy2"
            first = forwarded.split(",")[0].strip()
            if first:
                return first
    # Fallback to the direct TCP peer.
    if request.client and request.client.host:
        return request.client.host
    return "unknown"
