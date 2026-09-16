"""Fill the database with two clinics so there is something to test against.

Two clinics matter more than one: a single clinic can never show that the
isolation works. The same patient email exists at both on purpose — that is the
case that proves emails are unique per clinic rather than globally.

Run with:  python -m scripts.seed
"""

import asyncio
import sys

from sqlalchemy import select

from app.core.security import hash_password
from app.database.models import Tenant, User, UserRole
from app.database.session import AsyncSessionLocal, engine

# example.com and its subdomains are reserved by RFC 2606, so none of these
# can ever reach a real inbox. Note what is NOT used here: .test is reserved by
# the same standard, but the email checking library refuses reserved names like
# .test and .local outright, so accounts seeded with them could be written
# straight to the database and then never log in through the API.
PASSWORD = "seedpassword123"

CLINICS = [
    {
        "name": "Riverside Family Practice",
        "slug": "riverside",
        "people": [
            ("admin@riverside.example.com", "Nadia Okafor", UserRole.ADMIN),
            ("dr.chen@riverside.example.com", "Dr Wei Chen", UserRole.PROVIDER),
            ("dr.patel@riverside.example.com", "Dr Anaya Patel", UserRole.PROVIDER),
            ("sarah@example.com", "Sarah Lindqvist", UserRole.PATIENT),
            ("tom@example.com", "Tom Bergeron", UserRole.PATIENT),
        ],
    },
    {
        "name": "Northgate Specialist Centre",
        "slug": "northgate",
        "people": [
            ("admin@northgate.example.com", "Marcus Bell", UserRole.ADMIN),
            ("dr.suzuki@northgate.example.com", "Dr Rin Suzuki", UserRole.PROVIDER),
            # Same address as Riverside's patient, deliberately. Different
            # person as far as the system is concerned, different records.
            ("sarah@example.com", "Sarah Lindqvist", UserRole.PATIENT),
        ],
    },
]


async def reset() -> None:
    """Delete the seeded clinics. Everything belonging to them goes too, via
    the ON DELETE CASCADE on tenant_id."""
    async with AsyncSessionLocal() as db:
        for spec in CLINICS:
            clinic = await db.scalar(select(Tenant).where(Tenant.slug == spec["slug"]))
            if clinic is not None:
                await db.delete(clinic)
                print(f"  {spec['slug']}: removed")
        await db.commit()


async def seed() -> None:
    async with AsyncSessionLocal() as db:
        for spec in CLINICS:
            existing = await db.scalar(
                select(Tenant).where(Tenant.slug == spec["slug"])
            )
            if existing is not None:
                print(f"  {spec['slug']}: already there, skipping")
                continue

            clinic = Tenant(name=spec["name"], slug=spec["slug"])
            db.add(clinic)
            await db.flush()

            for email, full_name, role in spec["people"]:
                db.add(
                    User(
                        tenant_id=clinic.id,
                        email=email,
                        hashed_password=hash_password(PASSWORD),
                        full_name=full_name,
                        role=role,
                    )
                )
            await db.commit()
            print(f"  {spec['slug']}: {len(spec['people'])} people")


async def main() -> None:
    """One async run for the whole script, however many steps it has.

    Each asyncio.run() opens an event loop and closes it on the way out, while
    the connection pool in app.database.session is created once at import and
    shared. Two asyncio.run() calls therefore hand the second one connections
    belonging to a loop that has already shut down, and asyncpg rejects them
    with "attached to a different loop". One run, one loop, no mismatch.
    """
    try:
        if "--reset" in sys.argv:
            print("Clearing seeded clinics")
            await reset()
        print(f"Seeding. Every account's password is: {PASSWORD}")
        await seed()
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
