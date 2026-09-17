"""Tokens that have been cancelled before their own expiry.

A signed token cannot be withdrawn — once handed out, it stays valid until its
expiry passes, and nothing we do to our own records changes that. So logging
out means keeping a list of tokens we no longer honour, and checking it.

The list only has to remember a token until the moment it would have expired
anyway, because after that it is refused for being stale regardless. Every
entry is given exactly that long to live, so Redis empties the list itself and
it cannot grow without bound.
"""

import uuid
from datetime import datetime, timezone

from redis.asyncio import Redis

from app.core.tokens import TokenClaims

KEY_PREFIX = "revoked:"


def _key(jti: uuid.UUID) -> str:
    return f"{KEY_PREFIX}{jti}"


class RevokedTokens:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def revoke(self, claims: TokenClaims) -> int:
        """Stop honouring this one token. Returns the seconds it is remembered.

        A token that has already expired is not worth storing — it is refused
        on its own expiry, and an entry for it would just be litter.
        """
        remaining = int((claims.exp - datetime.now(timezone.utc)).total_seconds())
        if remaining <= 0:
            return 0
        await self._redis.set(_key(claims.jti), "1", ex=remaining)
        return remaining

    async def is_revoked(self, jti: uuid.UUID) -> bool:
        return await self._redis.exists(_key(jti)) == 1
