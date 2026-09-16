"""Puts the rate limiter in front of a route."""

from fastapi import HTTPException, Request, status

from app.core.config import settings
from app.core.rate_limit import RateLimiter


def caller_address(request: Request) -> str:
    """Who the attempts get counted against."""
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # The first entry is the original caller; the rest are the proxies
            # it passed through on the way here.
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimit:
    """Use as a dependency: Depends(RateLimit("login")).

    Each scope counts separately, so burning the login allowance does not also
    lock someone out of signing up a clinic.
    """

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
        decision = await limiter.check(
            key, limit=self.limit, window_seconds=self.window_seconds
        )

        if not decision.allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts. Try again shortly.",
                # Tells a well-behaved client exactly how long to wait instead
                # of leaving it to guess and keep hammering.
                headers={"Retry-After": str(decision.retry_after_seconds)},
            )
