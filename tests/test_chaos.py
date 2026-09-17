"""Phase 8 — what happens when a dependency is actually gone.

Nothing here is mocked. Redis and Postgres are pointed at ports with nothing
listening on them, so the failures are real connection failures.
"""

import pytest
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database.session import get_db
from app.main import app

DEAD_REDIS = "redis://127.0.0.1:6399/0"
DEAD_POSTGRES = "postgresql+asyncpg://healthcare:healthcare@127.0.0.1:5499/healthcare"


@pytest.fixture
async def redis_is_gone():
    """Swap in a Redis pointing at a closed port, then put the real one back."""
    real = app.state.redis
    app.state.redis = Redis.from_url(
        DEAD_REDIS, decode_responses=True, socket_connect_timeout=1, socket_timeout=1
    )
    yield
    await app.state.redis.aclose()
    app.state.redis = real


@pytest.fixture
async def postgres_is_gone():
    engine = create_async_engine(DEAD_POSTGRES, pool_pre_ping=False)
    Session = async_sessionmaker(engine)

    async def broken_db():
        async with Session() as session:
            yield session

    app.dependency_overrides[get_db] = broken_db
    yield
    app.dependency_overrides.pop(get_db, None)
    await engine.dispose()


# --- Redis unreachable ------------------------------------------------------


async def test_login_refuses_rather_than_skipping_the_limit(
    client, clinic, redis_is_gone
):
    """Fail closed.

    Letting logins through when the counter is unreachable would mean an
    outage silently removes brute-force protection from the one page worth
    attacking during an outage.
    """
    r = await client.post(
        "/auth/login",
        headers={"X-Tenant-Slug": clinic.slug},
        json={"email": clinic.admin.email, "password": clinic.password},
    )
    assert r.status_code == 503, f"expected a refusal, got {r.status_code}"
    assert r.headers["retry-after"] == "30"


async def test_it_is_a_503_and_not_a_500(client, clinic, redis_is_gone):
    """The difference matters: 500 means we are broken, 503 means try again."""
    r = await client.post(
        "/auth/login",
        headers={"X-Tenant-Slug": clinic.slug},
        json={"email": clinic.admin.email, "password": clinic.password},
    )
    assert r.status_code == 503
    assert 500 != r.status_code


async def test_protected_routes_refuse_when_the_revocation_list_is_gone(
    client, clinic, redis_is_gone
):
    """We cannot tell a live token from one that was logged out. Refuse."""
    from app.core.tokens import create_access_token

    token = create_access_token(
        user_id=clinic.admin.id, tenant_id=clinic.id, role=clinic.admin.role
    ).token
    r = await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 503


async def test_the_outage_does_not_leak_connection_details(client, clinic, redis_is_gone):
    r = await client.post(
        "/auth/login",
        headers={"X-Tenant-Slug": clinic.slug},
        json={"email": clinic.admin.email, "password": clinic.password},
    )
    body = r.text.lower()
    for leak in ("6399", "127.0.0.1", "connection refused", "traceback"):
        assert leak not in body, f"the reply gave away {leak!r}"


async def test_health_still_answers_without_redis(client, redis_is_gone):
    """Something has to stay up to say the process is alive."""
    assert (await client.get("/health")).status_code == 200


# --- Postgres unreachable ---------------------------------------------------


async def test_database_gone_is_a_clean_503_not_a_crash(client, clinic, postgres_is_gone):
    r = await client.post(
        "/auth/login",
        headers={"X-Tenant-Slug": clinic.slug},
        json={"email": clinic.admin.email, "password": clinic.password},
    )
    assert r.status_code == 503, f"expected 503, got {r.status_code}"
    assert r.headers.get("retry-after") == "30"


async def test_database_outage_does_not_leak_the_connection_string(
    client, clinic, postgres_is_gone
):
    r = await client.post(
        "/auth/login",
        headers={"X-Tenant-Slug": clinic.slug},
        json={"email": clinic.admin.email, "password": clinic.password},
    )
    body = r.text.lower()
    for leak in ("5499", "healthcare:healthcare", "asyncpg", "traceback"):
        assert leak not in body, f"the reply gave away {leak!r}"


async def test_everything_recovers_afterwards(client, clinic):
    """No fixture here — the previous tests put things back."""
    r = await client.post(
        "/auth/login",
        headers={"X-Tenant-Slug": clinic.slug},
        json={"email": clinic.admin.email, "password": clinic.password},
    )
    assert r.status_code == 200
