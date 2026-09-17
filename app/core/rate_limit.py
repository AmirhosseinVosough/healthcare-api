"""A sliding-window rate limiter that runs as one indivisible step in Redis.

Why the counting does not happen in Python: reading the count, adding one and
writing it back is three separate trips. Ten requests arriving together all
read the same number before any of them writes it back, and all ten are let
through. The whole decision has to happen inside Redis, in one go.

Why not count per clock-minute: "requests since the top of the minute" lets
someone spend the full allowance at 11:00:59 and the full allowance again at
11:01:00 — twice the intended rate, one second apart. This keeps the time of
every recent attempt and asks how many fall within the last N seconds counted
backwards from now, so there is no boundary to straddle.
"""

import time
import uuid
from dataclasses import dataclass

from redis.asyncio import Redis

# KEYS[1] one caller's bucket
# ARGV[1] now, in milliseconds      ARGV[3] how many are allowed
# ARGV[2] window length, in ms      ARGV[4] a unique id for this attempt
#
# Redis runs a script start to finish with nothing else interleaved, so the
# counting and the decision cannot come apart.
SLIDING_WINDOW = """
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local member = ARGV[4]

-- Forget attempts that have aged out of the window.
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - window)

local used = redis.call('ZCARD', KEYS[1])

if used < limit then
    redis.call('ZADD', KEYS[1], now, member)
    redis.call('PEXPIRE', KEYS[1], window)
    return {1, limit - used - 1, 0}
end

-- Refused. Work out when the oldest attempt drops out and a slot frees up.
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
local wait = window
if oldest[2] then
    wait = (tonumber(oldest[2]) + window) - now
end
redis.call('PEXPIRE', KEYS[1], window)
return {0, 0, wait}
"""

# Guard 2 needs the count and the recording kept apart, because it only counts
# FAILURES. PEEK asks "is this account over its budget right now?" and records
# nothing, so a correct password can be checked without ever adding to the
# count. RECORD adds one failure, and is called only after a guess turns out
# to be wrong.
PEEK_WINDOW = """
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - window)
local used = redis.call('ZCARD', KEYS[1])
if used < limit then
    return {1, limit - used, 0}
end
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
local wait = window
if oldest[2] then
    wait = (tonumber(oldest[2]) + window) - now
end
return {0, 0, wait}
"""

RECORD_FAILURE = """
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
redis.call('ZADD', KEYS[1], now, ARGV[3])
redis.call('PEXPIRE', KEYS[1], window)
return redis.call('ZCARD', KEYS[1])
"""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    remaining: int
    retry_after_seconds: int


class RateLimiter:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis
        # register_script sends the body once, then calls it by its hash, so
        # the script is not shipped over the wire on every request.
        self._script = redis.register_script(SLIDING_WINDOW)
        self._peek = redis.register_script(PEEK_WINDOW)
        self._record = redis.register_script(RECORD_FAILURE)

    async def check(self, key: str, *, limit: int, window_seconds: int) -> Decision:
        now_ms = int(time.time() * 1000)
        allowed, remaining, wait_ms = await self._script(
            keys=[key],
            args=[now_ms, window_seconds * 1000, limit, uuid.uuid4().hex],
        )
        allowed = bool(allowed)
        return Decision(
            allowed=allowed,
            remaining=int(remaining),
            # Round up, so 200ms left is reported as 1 second rather than 0.
            retry_after_seconds=0 if allowed else max(1, -(-int(wait_ms) // 1000)),
        )

    async def peek(self, key: str, *, limit: int, window_seconds: int) -> Decision:
        """Is this key over its budget right now? Records nothing.

        Used by the per-account guard before the password is checked, so a
        correct password is never blocked by a full budget.
        """
        now_ms = int(time.time() * 1000)
        allowed, remaining, wait_ms = await self._peek(
            keys=[key], args=[now_ms, window_seconds * 1000, limit]
        )
        allowed = bool(allowed)
        return Decision(
            allowed=allowed,
            remaining=int(remaining),
            retry_after_seconds=0 if allowed else max(1, -(-int(wait_ms) // 1000)),
        )

    async def record_failure(self, key: str, *, window_seconds: int) -> int:
        """Add one failure to a key's window. Returns the new count."""
        now_ms = int(time.time() * 1000)
        return int(
            await self._record(
                keys=[key], args=[now_ms, window_seconds * 1000, uuid.uuid4().hex]
            )
        )

    async def clear(self, key: str) -> None:
        """Wipe a key. Called on a successful login, so a real user starts
        fresh the moment they get it right."""
        await self._redis.delete(key)
