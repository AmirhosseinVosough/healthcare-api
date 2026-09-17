"""Phase 6 — rate limiting on the two doors that take a password."""

import asyncio
import uuid

import pytest

from app.core.rate_limit import RateLimiter
from app.core.redis import create_redis


@pytest.fixture
async def redis():
    client = create_redis()
    yield client
    await client.aclose()


@pytest.fixture
def bucket():
    """A key nobody else is using, so tests cannot interfere with each other."""
    return f"ratelimit:test:{uuid.uuid4().hex}"


# --- the limiter itself -----------------------------------------------------


async def test_allows_up_to_the_limit_then_refuses(redis, bucket):
    limiter = RateLimiter(redis)
    for attempt in range(5):
        decision = await limiter.check(bucket, limit=5, window_seconds=60)
        assert decision.allowed, f"attempt {attempt + 1} of 5 was refused"

    sixth = await limiter.check(bucket, limit=5, window_seconds=60)
    assert not sixth.allowed
    assert sixth.retry_after_seconds > 0


async def test_remaining_counts_down(redis, bucket):
    limiter = RateLimiter(redis)
    seen = [
        (await limiter.check(bucket, limit=3, window_seconds=60)).remaining
        for _ in range(3)
    ]
    assert seen == [2, 1, 0]


async def test_separate_callers_get_separate_allowances(redis):
    limiter = RateLimiter(redis)
    mine = f"ratelimit:test:{uuid.uuid4().hex}"
    theirs = f"ratelimit:test:{uuid.uuid4().hex}"

    for _ in range(5):
        await limiter.check(mine, limit=5, window_seconds=60)

    assert not (await limiter.check(mine, limit=5, window_seconds=60)).allowed
    assert (await limiter.check(theirs, limit=5, window_seconds=60)).allowed


async def test_the_window_slides_rather_than_resetting(redis, bucket):
    """The flaw a per-clock-minute counter has.

    Spend the whole allowance, wait for the window to pass, and it should open
    up again — but only because those attempts genuinely aged out, not because
    a clock ticked over. Run with a 1 second window so the test is quick.
    """
    limiter = RateLimiter(redis)
    for _ in range(3):
        assert (await limiter.check(bucket, limit=3, window_seconds=1)).allowed
    assert not (await limiter.check(bucket, limit=3, window_seconds=1)).allowed

    await asyncio.sleep(1.1)
    assert (await limiter.check(bucket, limit=3, window_seconds=1)).allowed


async def test_no_double_allowance_across_a_boundary(redis, bucket):
    """The specific bug a fixed window has.

    A per-minute counter lets someone spend the full allowance at the end of
    one minute and the full allowance again at the start of the next — twice
    the intended rate, moments apart. Here, five attempts spread over half a
    window must still leave no room for five more immediately after.
    """
    limiter = RateLimiter(redis)
    for _ in range(5):
        assert (await limiter.check(bucket, limit=5, window_seconds=2)).allowed
        await asyncio.sleep(0.1)

    await asyncio.sleep(1.0)  # over half the window has now passed
    decision = await limiter.check(bucket, limit=5, window_seconds=2)
    assert not decision.allowed, "a fixed window would have reset and allowed this"


async def test_counting_survives_a_stampede(redis, bucket):
    """Twenty requests at once against a limit of five.

    This is the case that a read-then-write counter in Python gets wrong: all
    twenty read the same number before any of them writes it back, and all
    twenty are let through. The script runs as one step, so exactly five win.
    """
    limiter = RateLimiter(redis)
    decisions = await asyncio.gather(
        *(limiter.check(bucket, limit=5, window_seconds=60) for _ in range(20))
    )
    allowed = [d for d in decisions if d.allowed]
    assert len(allowed) == 5, f"expected exactly 5 through, got {len(allowed)}"


# --- through the actual endpoints -------------------------------------------


async def test_sixth_login_attempt_is_refused(client, clinic):
    wrong = {"email": clinic.admin.email, "password": "definitely-not-it"}
    headers = {"X-Tenant-Slug": clinic.slug}

    codes = [
        (await client.post("/auth/login", headers=headers, json=wrong)).status_code
        for _ in range(6)
    ]
    assert codes[:5] == [401] * 5, f"first five should be plain refusals: {codes}"
    assert codes[5] == 429, f"sixth should be rate limited: {codes}"


async def test_the_429_says_how_long_to_wait(client, clinic):
    headers = {"X-Tenant-Slug": clinic.slug}
    wrong = {"email": clinic.admin.email, "password": "definitely-not-it"}

    for _ in range(5):
        await client.post("/auth/login", headers=headers, json=wrong)

    blocked = await client.post("/auth/login", headers=headers, json=wrong)
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0


async def test_the_limit_counts_attempts_not_failures(client, clinic):
    """Five correct logins in a row still exhaust the allowance.

    Counting only failures would let someone alternate a known-good login with
    guesses and never be limited.
    """
    headers = {"X-Tenant-Slug": clinic.slug}
    right = {"email": clinic.admin.email, "password": clinic.password}

    for _ in range(5):
        assert (
            await client.post("/auth/login", headers=headers, json=right)
        ).status_code == 200

    assert (
        await client.post("/auth/login", headers=headers, json=right)
    ).status_code == 429


async def test_signup_has_its_own_allowance(client, clinic):
    """Burning the login allowance must not close the signup door too."""
    headers = {"X-Tenant-Slug": clinic.slug}
    wrong = {"email": clinic.admin.email, "password": "definitely-not-it"}

    for _ in range(6):
        await client.post("/auth/login", headers=headers, json=wrong)

    slug = f"fresh-{uuid.uuid4().hex[:10]}"
    made = await client.post(
        "/auth/signup",
        json={
            "clinic_name": "Fresh Clinic",
            "clinic_slug": slug,
            "full_name": "Fresh Admin",
            "email": f"admin@{slug}.example.com",
            "password": "freshpassword1",
        },
    )
    assert made.status_code == 201, "signup should not be blocked by login attempts"

    from app.database.models import Tenant
    from app.database.session import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        await db.delete(await db.get(Tenant, uuid.UUID(made.json()["clinic"]["id"])))
        await db.commit()


async def test_booking_is_not_rate_limited(client, clinic):
    """The limit belongs on the doors that take a password, not on everything.

    Someone with a valid token using the app normally should never meet it.
    """
    from tests.test_appointments import auth

    for _ in range(10):
        r = await client.get("/appointments", headers=auth(clinic.admin))
        assert r.status_code == 200
