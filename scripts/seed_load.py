"""Fill the database with enough clinics to load test against.

Fifty clinics, each with an admin, two doctors and eight patients, plus a
scatter of existing appointments so the list endpoint has real work to do
rather than returning an empty array very quickly.

The password is hashed once and the result reused for every account. The cost
of verifying a bcrypt hash depends on the cost factor stored inside it, not on
which salt produced it, so logins during the load test cost exactly what a
real login costs — while seeding four hundred accounts takes a second instead
of two and a half minutes.

Run with:  python -m scripts.seed_load [--reset]
"""

import asyncio
import random
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text

from app.core.security import hash_password
from app.database.models import Appointment, Tenant, User, UserRole
from app.database.session import AsyncSessionLocal, engine, use_tenant

CLINIC_COUNT = 50
DOCTORS_PER_CLINIC = 2
PATIENTS_PER_CLINIC = 8
APPOINTMENTS_PER_CLINIC = 40
PASSWORD = "loadtestpassword1"
SLUG_PREFIX = "load"

FIRST = [
    "Amara",
    "Bo",
    "Chidi",
    "Dara",
    "Eli",
    "Freya",
    "Gus",
    "Hana",
    "Ines",
    "Jonas",
    "Kira",
    "Luca",
    "Mei",
    "Nils",
    "Omar",
    "Pia",
    "Quinn",
    "Rosa",
    "Sami",
    "Tova",
]
LAST = [
    "Abara",
    "Bergman",
    "Costa",
    "Duarte",
    "Eriksen",
    "Fontaine",
    "Gallo",
    "Haddad",
    "Ivanov",
    "Jensen",
    "Kowalski",
    "Laurent",
    "Moreau",
    "Nakamura",
    "Okonkwo",
    "Petrov",
    "Quiroga",
    "Rossi",
    "Silva",
    "Tanaka",
]


def name(rng: random.Random) -> str:
    return f"{rng.choice(FIRST)} {rng.choice(LAST)}"


async def reset() -> None:
    async with AsyncSessionLocal() as db:
        doomed = (
            await db.scalars(select(Tenant).where(Tenant.slug.like(f"{SLUG_PREFIX}-%")))
        ).all()
        for clinic in doomed:
            await db.delete(clinic)
        await db.commit()
        print(f"  removed {len(doomed)} clinics")


async def build() -> None:
    rng = random.Random(20260917)  # fixed, so every run is the same shape
    shared_hash = hash_password(PASSWORD)
    made = 0

    async with AsyncSessionLocal() as db:
        for n in range(CLINIC_COUNT):
            slug = f"{SLUG_PREFIX}-{n:03d}"
            if await db.scalar(select(Tenant).where(Tenant.slug == slug)):
                continue

            clinic = Tenant(name=f"Load Clinic {n:03d}", slug=slug)
            db.add(clinic)
            await db.flush()
            await use_tenant(db, clinic.id)

            people = []
            for index, role in (
                [(0, UserRole.ADMIN)]
                + [(i, UserRole.PROVIDER) for i in range(DOCTORS_PER_CLINIC)]
                + [(i, UserRole.PATIENT) for i in range(PATIENTS_PER_CLINIC)]
            ):
                person = User(
                    tenant_id=clinic.id,
                    email=f"{role.value}{index}@{slug}.example.com",
                    hashed_password=shared_hash,
                    full_name=name(rng),
                    role=role,
                )
                db.add(person)
                people.append(person)
            await db.flush()

            doctors = [p for p in people if p.role is UserRole.PROVIDER]
            patients = [p for p in people if p.role is UserRole.PATIENT]

            # Spread bookings over the next few weeks, on the half hour, so no
            # two for one doctor collide and the exclusion constraint is not
            # what we end up measuring.
            base = datetime.now(UTC).replace(
                minute=0, second=0, microsecond=0
            ) + timedelta(days=1)
            for slot in range(APPOINTMENTS_PER_CLINIC):
                doctor = doctors[slot % len(doctors)]
                start = base + timedelta(minutes=30 * (slot // len(doctors)))
                db.add(
                    Appointment(
                        tenant_id=clinic.id,
                        patient_id=rng.choice(patients).id,
                        provider_id=doctor.id,
                        scheduled_start=start,
                        scheduled_end=start + timedelta(minutes=30),
                        reason="Routine review",
                    )
                )

            await db.commit()
            made += 1
            if made % 10 == 0:
                print(f"  {made} clinics")

    # Counting has to be done clinic by clinic. A plain
    # `SELECT count(*) FROM users` here returns zero, because this session has
    # not said which clinic it is and the policy answers accordingly — which
    # is the whole point, and is easy to mistake for a failed seed.
    async with AsyncSessionLocal() as db:
        clinics = (
            await db.scalars(select(Tenant).where(Tenant.slug.like(f"{SLUG_PREFIX}-%")))
        ).all()
        users = appointments = 0
        for clinic in clinics:
            await use_tenant(db, clinic.id)
            users += await db.scalar(text("SELECT count(*) FROM users"))
            appointments += await db.scalar(text("SELECT count(*) FROM appointments"))
            await db.commit()  # SET LOCAL dies here, so each loop re-sets it
    print(f"  {len(clinics)} clinics, {users} users, {appointments} appointments")


async def main() -> None:
    try:
        if "--reset" in sys.argv:
            await reset()
        await build()
    finally:
        await engine.dispose()


if __name__ == "__main__":
    print(f"Seeding {CLINIC_COUNT} clinics. Password: {PASSWORD}")
    asyncio.run(main())
