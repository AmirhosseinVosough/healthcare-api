"""Phase 4 — turning a token into the person it belongs to."""

import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from sqlalchemy import update

from app.core.config import settings
from app.core.tokens import create_access_token, create_refresh_token
from app.database.models import Tenant, User, UserRole
from app.database.session import AsyncSessionLocal


def token_for(user: User) -> str:
    return create_access_token(
        user_id=user.id, tenant_id=user.tenant_id, role=user.role
    ).token


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- the happy path ---------------------------------------------------------


async def test_me_returns_the_caller(client, clinic):
    r = await client.get("/auth/me", headers=auth(token_for(clinic.patient)))
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == str(clinic.patient.id)
    assert body["tenant_id"] == str(clinic.id)
    assert body["email"] == clinic.patient.email
    assert body["role"] == "patient"


async def test_me_never_returns_the_password_hash(client, clinic):
    r = await client.get("/auth/me", headers=auth(token_for(clinic.admin)))
    assert "hashed_password" not in r.json()
    assert "$2b$" not in r.text


async def test_the_whole_chain_from_login(client, clinic):
    """Log in for real, then use what login handed back."""
    login = await client.post(
        "/auth/login",
        headers={"X-Tenant-Slug": clinic.slug},
        json={"email": clinic.admin.email, "password": clinic.password},
    )
    assert login.status_code == 200
    r = await client.get("/auth/me", headers=auth(login.json()["access_token"]))
    assert r.status_code == 200
    assert r.json()["tenant_id"] == str(clinic.id)
    assert r.json()["role"] == "admin"


async def test_two_clinics_get_their_own_answer(client, clinic):
    """Same route, two tokens, two clinics. Neither sees the other."""
    async with AsyncSessionLocal() as db:
        other = Tenant(name="Other", slug=f"other-{uuid.uuid4().hex[:10]}")
        db.add(other)
        await db.flush()
        stranger = User(
            tenant_id=other.id,
            email=f"x@{other.slug}.example.com",
            hashed_password="$2b$04$irrelevant",
            full_name="Stranger",
            role=UserRole.PATIENT,
        )
        db.add(stranger)
        await db.commit()
        stranger_token = token_for(stranger)
        other_id = other.id

    mine = await client.get("/auth/me", headers=auth(token_for(clinic.patient)))
    theirs = await client.get("/auth/me", headers=auth(stranger_token))
    assert mine.json()["tenant_id"] == str(clinic.id)
    assert theirs.json()["tenant_id"] == str(other_id)
    assert mine.json()["tenant_id"] != theirs.json()["tenant_id"]

    async with AsyncSessionLocal() as db:
        await db.delete(await db.get(Tenant, other_id))
        await db.commit()


# --- everything that must be turned away ------------------------------------


async def test_no_token_at_all(client):
    r = await client.get("/auth/me")
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "header",
    [
        {},
        {"Authorization": ""},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer "},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer not-a-token"},
        {"Authorization": "Bearer a.b.c"},
    ],
)
async def test_malformed_credentials(client, header):
    assert (await client.get("/auth/me", headers=header)).status_code == 401


async def test_refresh_token_is_not_an_access_token(client, clinic):
    """A refresh token lives a week. It must not open doors for that week."""
    refresh = create_refresh_token(
        user_id=clinic.patient.id,
        tenant_id=clinic.id,
        role=UserRole.PATIENT,
    ).token
    assert (await client.get("/auth/me", headers=auth(refresh))).status_code == 401


async def test_expired_token(client, clinic):
    now = datetime.now(timezone.utc)
    stale = jwt.encode(
        {
            "sub": str(clinic.patient.id),
            "tid": str(clinic.id),
            "role": "patient",
            "jti": str(uuid.uuid4()),
            "typ": "access",
            "iat": now - timedelta(hours=2),
            "exp": now - timedelta(hours=1),
        },
        settings.jwt_secret,
        algorithm="HS256",
    )
    assert (await client.get("/auth/me", headers=auth(stale))).status_code == 401


async def test_token_signed_with_a_different_key(client, clinic):
    now = datetime.now(timezone.utc)
    forged = jwt.encode(
        {
            "sub": str(clinic.admin.id),
            "tid": str(clinic.id),
            "role": "admin",
            "jti": str(uuid.uuid4()),
            "typ": "access",
            "iat": now,
            "exp": now + timedelta(minutes=15),
        },
        "an-attacker-secret-long-enough-for-hs256",
        algorithm="HS256",
    )
    assert (await client.get("/auth/me", headers=auth(forged))).status_code == 401


async def test_token_naming_the_wrong_clinic(client, clinic):
    """Correctly signed, real user, but the clinic claim has been swapped.

    The lookup matches on user AND clinic together, so this finds nobody.
    """
    now = datetime.now(timezone.utc)
    mismatched = jwt.encode(
        {
            "sub": str(clinic.patient.id),
            "tid": str(uuid.uuid4()),  # a clinic this user does not belong to
            "role": "patient",
            "jti": str(uuid.uuid4()),
            "typ": "access",
            "iat": now,
            "exp": now + timedelta(minutes=15),
        },
        settings.jwt_secret,
        algorithm="HS256",
    )
    assert (await client.get("/auth/me", headers=auth(mismatched))).status_code == 401


async def test_deactivated_user(client, clinic):
    """The token is still valid for 15 minutes. The account is not."""
    token = token_for(clinic.patient)
    assert (await client.get("/auth/me", headers=auth(token))).status_code == 200

    async with AsyncSessionLocal() as db:
        await db.execute(
            update(User).where(User.id == clinic.patient.id).values(is_active=False)
        )
        await db.commit()

    assert (await client.get("/auth/me", headers=auth(token))).status_code == 401


async def test_deactivated_clinic(client, clinic):
    """Closing a clinic locks out everyone in it, without waiting for expiry."""
    token = token_for(clinic.admin)
    assert (await client.get("/auth/me", headers=auth(token))).status_code == 200

    async with AsyncSessionLocal() as db:
        await db.execute(
            update(Tenant).where(Tenant.id == clinic.id).values(is_active=False)
        )
        await db.commit()

    assert (await client.get("/auth/me", headers=auth(token))).status_code == 401


async def test_deleted_user(client, clinic):
    token = token_for(clinic.patient)
    async with AsyncSessionLocal() as db:
        await db.delete(await db.get(User, clinic.patient.id))
        await db.commit()

    assert (await client.get("/auth/me", headers=auth(token))).status_code == 401


async def test_every_refusal_looks_the_same(client, clinic):
    """A 401 must not hint at which of the many reasons it was."""
    bodies = set()
    for header in (
        {},
        {"Authorization": "Bearer garbage"},
        auth(
            create_refresh_token(
                user_id=clinic.patient.id, tenant_id=clinic.id, role=UserRole.PATIENT
            ).token
        ),
    ):
        r = await client.get("/auth/me", headers=header)
        assert r.status_code == 401
        bodies.add(r.text)
    assert len(bodies) == 1, f"refusals differ: {bodies}"
