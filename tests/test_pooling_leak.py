"""Phase 8 — the bug inside the mechanism meant to prevent leaks.

Row-level security reads the clinic from a setting on the database session.
Set that with plain SET and it belongs to the *connection*, not the request.
Connections are pooled and handed to whoever asks next, so the setting rides
along into the next request — possibly a different clinic's.

These tests reproduce that first, then show the fix, so the difference is
demonstrated rather than asserted. Written up in docs/rls-pooling-bug.md.
"""

import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import settings
from app.core.security import hash_password
from app.database.models import Tenant, User, UserRole
from app.database.session import AsyncSessionLocal, use_tenant


@pytest.fixture
async def one_connection_engine():
    """Exactly one connection, so the next request must reuse the last one.

    A larger pool hides this: two requests land on two different connections
    and the leak never shows. Production hides it the same way, until load
    rises and connections start being shared.
    """
    engine = create_async_engine(
        settings.database_url, pool_size=1, max_overflow=0, pool_pre_ping=False
    )
    yield engine
    await engine.dispose()


@pytest.fixture
async def two_clinics():
    made = []
    for name in ("Leak A", "Leak B"):
        slug = f"leak-{uuid.uuid4().hex[:10]}"
        async with AsyncSessionLocal() as db:
            tenant = Tenant(name=name, slug=slug)
            db.add(tenant)
            await db.flush()
            await use_tenant(db, tenant.id)
            db.add(
                User(
                    tenant_id=tenant.id,
                    email=f"someone@{slug}.example.com",
                    hashed_password=hash_password("leakpassword1"),
                    full_name=f"{name} person",
                    role=UserRole.PATIENT,
                )
            )
            await db.commit()
            made.append(tenant.id)

    yield made

    for tenant_id in made:
        async with AsyncSessionLocal() as db:
            doomed = await db.get(Tenant, tenant_id)
            if doomed is not None:
                await db.delete(doomed)
                await db.commit()


async def test_plain_set_leaks_into_the_next_request(one_connection_engine, two_clinics):
    """The bug. Reproduced deliberately, with the wrong kind of SET.

    Clinic A makes a request. Clinic B's request arrives next, is handed the
    same physical connection, and finds Clinic A's identity still sitting on
    it. If Clinic B's request then failed to set its own — a missed
    dependency, a background job, a new endpoint someone forgot to wire — it
    would read Clinic A's rows while believing itself safe.
    """
    a_id, b_id = two_clinics
    Session = async_sessionmaker(one_connection_engine, expire_on_commit=False)

    # Request one, as Clinic A, using plain SET.
    async with Session() as db:
        await db.execute(text(f"SET app.tenant_id = '{a_id}'"))
        assert len((await db.scalars(select(User))).all()) == 1
        await db.commit()

    # The connection goes back to the pool. Request two picks it up.
    async with Session() as db:
        left_behind = await db.scalar(
            text("SELECT current_setting('app.tenant_id', true)")
        )

    assert left_behind == str(a_id), (
        "expected the leak to reproduce; if this fails the demonstration is "
        "no longer demonstrating anything"
    )

    # And it is not merely cosmetic — the rows really are visible.
    async with Session() as db:
        stranger_rows = (await db.scalars(select(User))).all()
        assert [u.tenant_id for u in stranger_rows] == [a_id]
        # Clean the connection before handing it back, so the fixed test below
        # starts from a known state.
        await db.execute(text("RESET app.tenant_id"))
        await db.commit()


async def test_set_local_does_not_leak(one_connection_engine, two_clinics):
    """The fix. Same pool of one, same reuse, no leak.

    SET LOCAL ties the setting to the transaction. The transaction ends at
    commit or rollback, and the setting goes with it — whatever the pool does
    with the connection afterwards.
    """
    a_id, _ = two_clinics
    Session = async_sessionmaker(one_connection_engine, expire_on_commit=False)

    async with Session() as db:
        await use_tenant(db, a_id)  # the function form of SET LOCAL
        assert len((await db.scalars(select(User))).all()) == 1
        await db.commit()

    async with Session() as db:
        left_behind = await db.scalar(
            text("SELECT current_setting('app.tenant_id', true)")
        )
        assert left_behind in (None, ""), f"the clinic leaked: {left_behind!r}"

        # And with nothing set, the policy shows nothing at all — which is the
        # safe direction to fail in.
        assert (await db.scalars(select(User))).all() == []


async def test_a_rollback_also_clears_it(one_connection_engine, two_clinics):
    """Not just commits. A failed request must not leave its clinic behind."""
    a_id, _ = two_clinics
    Session = async_sessionmaker(one_connection_engine, expire_on_commit=False)

    async with Session() as db:
        await use_tenant(db, a_id)
        await db.rollback()

    async with Session() as db:
        left_behind = await db.scalar(
            text("SELECT current_setting('app.tenant_id', true)")
        )
    assert left_behind in (None, "")
