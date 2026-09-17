"""Redis connection, opened once for the life of the app."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from redis.asyncio import Redis

from app.core.config import settings
from app.core.logging import configure_logging


def create_redis() -> Redis:
    return Redis.from_url(
        settings.redis_url,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
        health_check_interval=30,
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """One connection pool for the whole app, closed on the way out.

    Opened here rather than per request: dialling Redis fresh on every login
    would cost more than the check it exists to perform.
    """
    # First thing, so anything logged during startup is actually emitted.
    configure_logging()
    app.state.redis = create_redis()
    try:
        yield
    finally:
        await app.state.redis.aclose()
