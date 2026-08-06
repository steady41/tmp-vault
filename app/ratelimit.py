from dataclasses import dataclass

from fastapi import HTTPException, Request

from .config import Settings


@dataclass
class RateLimitResult:
    limit: int
    remaining: int


async def enforce_create_rate_limit(request: Request) -> RateLimitResult:
    """Fixed one-minute window per client IP, tracked in Redis."""
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
    if settings.trust_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
