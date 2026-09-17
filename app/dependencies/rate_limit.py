"""The two guards on the login door.

Guard 1 (this file's caller_address + RateLimit) counts guesses per caller.
Guard 2 (the per-account limit) lives in the login route, because it needs the
email, and is built on the same RateLimiter underneath.
"""

from fastapi import HTTPException, Request, status
from redis.exceptions import RedisError

from app.core.config import settings
from app.core.rate_limit import RateLimiter


def caller_address(request: Request) -> str:
    """Work out who actually sent the request.

    request.client.host is the address that genuinely opened the connection,
    which the caller cannot fake. X-Forwarded-For is a header the caller writes
    themselves, so it is only believed when the connection came from one of our
    own trusted proxies — because only then did that proxy write the header.

    When trusted, the RIGHTMOST entry is the one our proxy added; the entries
    to the left of it can be anything the caller pre-loaded, so they are
    ignored. With no trusted proxies configured (the default), the header is
    never read at all.
    """
    peer = request.client.host if request.client else "unknown"

    if peer in settings.trusted_proxies:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            hops = [h.strip() for h in forwarded.split(",") if h.strip()]
            if hops:
                return hops[-1]
    return peer


class RateLimit:
    """Guard 1, as a dependency: Depends(RateLimit("login"))."""

    def __init__(
        self,
        scope: str,
        limit: int | None = None,
        window_seconds: int | None = None,
    ) -> None:
        self.scope = scope
        self.limit = limit if limit is not None else settings.auth_rate_limit
        self.window_seconds = (
            window_seconds
            if window_seconds is not None
            else settings.auth_rate_window_seconds
        )

    async def __call__(self, request: Request) -> None:
        if not settings.rate_limit_enabled:
            return

        limiter = RateLimiter(request.app.state.redis)
        key = f"ratelimit:{self.scope}:{caller_address(request)}"
        try:
            decision = await limiter.check(
                key, limit=self.limit, window_seconds=self.window_seconds
            )
        except (RedisError, OSError) as exc:
            # Fail closed: if we cannot count, we do not take the attempt.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Login is briefly unavailable. Please try again shortly.",
                headers={"Retry-After": "30"},
            ) from exc

        if not decision.allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts. Try again shortly.",
                headers={"Retry-After": str(decision.retry_after_seconds)},
            )
