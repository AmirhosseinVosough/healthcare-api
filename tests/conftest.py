import os

# Set before anything imports app.core.config, which builds its settings (and
# the bcrypt context) at import time. Cost factor 4 instead of the real 12:
# the suite calls the hasher dozens of times and 12 costs ~370ms a call.
os.environ.setdefault("BCRYPT_ROUNDS", "4")

import uuid  # noqa: E402
from dataclasses import dataclass  # noqa: E402

import httpx  # noqa: E402
import pytest  # noqa: E402

from app.core.security import hash_password  # noqa: E402
from app.database.models import Tenant, User, UserRole  # noqa: E402
from app.database.session import AsyncSessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
async def _close_pooled_connections():
    """Empty the connection pool after every test.

    pytest gives each test its own event loop, and a database connection
    belongs to the loop that opened it. Without this, test two is handed a
    connection created for test one, whose loop is already gone, and asyncpg
    rejects it — the same fault that broke `seed --reset`.
    """
    yield
    await engine.dispose()


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@dataclass
class Clinic:
    """A throwaway clinic, deleted once the test that asked for it is done."""

    id: uuid.UUID
    slug: str
    admin: User
    patient: User
    provider: User
    password: str


@pytest.fixture
async def clinic():
    slug = f"test-{uuid.uuid4().hex[:12]}"
    password = "clinicpassword1"

    async with AsyncSessionLocal() as db:
        tenant = Tenant(name=f"Test Clinic {slug}", slug=slug)
        db.add(tenant)
        await db.flush()
        people = {}
        for role in (UserRole.ADMIN, UserRole.PATIENT, UserRole.PROVIDER):
            person = User(
                tenant_id=tenant.id,
                email=f"{role.value}@{slug}.example.com",
                hashed_password=hash_password(password),
                full_name=f"Test {role.value}",
                role=role,
            )
            db.add(person)
            people[role] = person
        await db.commit()
        made = Clinic(
            id=tenant.id,
            slug=slug,
            admin=people[UserRole.ADMIN],
            patient=people[UserRole.PATIENT],
            provider=people[UserRole.PROVIDER],
            password=password,
        )

    yield made

    async with AsyncSessionLocal() as db:
        doomed = await db.get(Tenant, made.id)
        if doomed is not None:
            await db.delete(doomed)  # users cascade away with it
            await db.commit()
