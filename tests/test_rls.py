"""Phase 8 — Postgres refusing other clinics' rows on its own.

Everything so far relies on the application writing `WHERE tenant_id = ...`
on every query. These tests take that away deliberately and check nothing
leaks anyway.
"""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text

from app.core.security import hash_password
from app.core.tokens import create_access_token
from app.database.models import Appointment, Tenant, User, UserRole
from app.database.session import AsyncSessionLocal, use_tenant


async def make_clinic(name: str) -> tuple[uuid.UUID, dict]:
    slug = f"rls-{uuid.uuid4().hex[:10]}"
    async with AsyncSessionLocal() as db:
        tenant = Tenant(name=name, slug=slug)
        db.add(tenant)
        await db.flush()
        await use_tenant(db, tenant.id)
        people = {}
        for role in (UserRole.ADMIN, UserRole.PATIENT, UserRole.PROVIDER):
            person = User(
                tenant_id=tenant.id,
                email=f"{role.value}@{slug}.example.com",
                hashed_password=hash_password("rlspassword1"),
                full_name=f"{name} {role.value}",
                role=role,
            )
            db.add(person)
            people[role] = person
        await db.commit()
        return tenant.id, people


async def drop_clinic(tenant_id: uuid.UUID) -> None:
    async with AsyncSessionLocal() as db:
        doomed = await db.get(Tenant, tenant_id)
        if doomed is not None:
            await db.delete(doomed)
            await db.commit()


async def test_with_no_clinic_declared_you_see_nothing():
    """The safe way round: forgetting to say who you are shows you nobody."""
    async with AsyncSessionLocal() as db:
        users = (await db.scalars(select(User))).all()
        appointments = (await db.scalars(select(Appointment))).all()
    assert users == []
    assert appointments == []


async def test_a_query_with_no_where_clause_still_cannot_cross_clinics():
    """The headline. `SELECT * FROM users` returns only your own clinic."""
    a_id, _ = await make_clinic("Clinic A")
    b_id, _ = await make_clinic("Clinic B")
    try:
        async with AsyncSessionLocal() as db:
            await use_tenant(db, a_id)
            # No filter of any kind. Postgres applies one.
            seen = (await db.scalars(select(User))).all()
        assert len(seen) == 3
        assert {u.tenant_id for u in seen} == {a_id}
    finally:
        await drop_clinic(a_id)
        await drop_clinic(b_id)


async def test_looking_up_another_clinics_appointment_by_id_finds_nothing():
    """The Phase 5 test, with the application's own filter taken away.

    Phase 5 proved the route adds `AND tenant_id = ...`. This proves that if
    someone deletes that line, the answer does not change.
    """
    a_id, a_people = await make_clinic("Clinic A")
    b_id, _ = await make_clinic("Clinic B")
    try:
        start = datetime.now(UTC) + timedelta(days=10)
        async with AsyncSessionLocal() as db:
            await use_tenant(db, a_id)
            booking = Appointment(
                tenant_id=a_id,
                patient_id=a_people[UserRole.PATIENT].id,
                provider_id=a_people[UserRole.PROVIDER].id,
                scheduled_start=start,
                scheduled_end=start + timedelta(minutes=30),
            )
            db.add(booking)
            await db.commit()
            booking_id = booking.id

        # Clinic A can see its own.
        async with AsyncSessionLocal() as db:
            await use_tenant(db, a_id)
            mine = await db.scalar(
                select(Appointment).where(Appointment.id == booking_id)
            )
        assert mine is not None

        # Clinic B runs the identical query — the tenant condition removed,
        # exactly as if a developer had forgotten it.
        async with AsyncSessionLocal() as db:
            await use_tenant(db, b_id)
            theirs = await db.scalar(
                select(Appointment).where(Appointment.id == booking_id)
            )
        assert theirs is None, "row-level security did not hold on its own"
    finally:
        await drop_clinic(a_id)
        await drop_clinic(b_id)


async def test_cannot_write_a_row_into_another_clinic():
    a_id, _ = await make_clinic("Clinic A")
    b_id, _ = await make_clinic("Clinic B")
    try:
        async with AsyncSessionLocal() as db:
            await use_tenant(db, a_id)
            db.add(
                User(
                    tenant_id=b_id,  # somebody else's clinic
                    email=f"sneak-{uuid.uuid4().hex[:8]}@example.com",
                    hashed_password="$2b$04$irrelevant",
                    full_name="Sneaky",
                    role=UserRole.PATIENT,
                )
            )
            try:
                await db.commit()
                raise AssertionError("the write was allowed")
            except Exception as exc:
                assert "row-level security" in str(exc).lower()
    finally:
        await drop_clinic(a_id)
        await drop_clinic(b_id)


async def test_the_setting_is_dropped_at_the_end_of_each_transaction():
    """SET LOCAL, not SET. The clinic must not survive its transaction."""
    a_id, _ = await make_clinic("Clinic A")
    try:
        async with AsyncSessionLocal() as db:
            await use_tenant(db, a_id)
            during = await db.scalar(
                text("SELECT current_setting('app.tenant_id', true)")
            )
            assert during == str(a_id)
            await db.commit()  # the transaction ends here

            after = await db.scalar(text("SELECT current_setting('app.tenant_id', true)"))
        assert after in (None, ""), f"the clinic outlived its transaction: {after!r}"
    finally:
        await drop_clinic(a_id)


async def test_the_api_still_works_with_policies_on(client, clinic):
    """Belt and braces: the normal path is unaffected."""
    token = create_access_token(
        user_id=clinic.admin.id, tenant_id=clinic.id, role=UserRole.ADMIN
    ).token
    r = await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["tenant_id"] == str(clinic.id)
