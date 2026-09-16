"""Phase 5 — appointments, clinic isolation, and the double-booking race."""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.core.security import hash_password
from app.core.tokens import create_access_token
from app.database.models import Tenant, User, UserRole
from app.database.session import AsyncSessionLocal
from app.main import app

SOON = datetime.now(timezone.utc) + timedelta(days=30)


def token_for(user: User) -> str:
    return create_access_token(
        user_id=user.id, tenant_id=user.tenant_id, role=user.role
    ).token


def auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {token_for(user)}"}


def booking(clinic, start: datetime = SOON, minutes: int = 30) -> dict:
    return {
        "patient_id": str(clinic.patient.id),
        "provider_id": str(clinic.provider.id),
        "scheduled_start": start.isoformat(),
        "scheduled_end": (start + timedelta(minutes=minutes)).isoformat(),
        "reason": "Check-up",
    }


async def make_second_clinic():
    """A whole separate clinic, for the cross-clinic tests."""
    slug = f"other-{uuid.uuid4().hex[:10]}"
    async with AsyncSessionLocal() as db:
        tenant = Tenant(name="Other Clinic", slug=slug)
        db.add(tenant)
        await db.flush()
        people = {}
        for role in (UserRole.ADMIN, UserRole.PATIENT, UserRole.PROVIDER):
            person = User(
                tenant_id=tenant.id,
                email=f"{role.value}@{slug}.example.com",
                hashed_password=hash_password("otherpassword1"),
                full_name=f"Other {role.value}",
                role=role,
            )
            db.add(person)
            people[role] = person
        await db.commit()
        return tenant.id, people


async def delete_clinic(tenant_id):
    async with AsyncSessionLocal() as db:
        doomed = await db.get(Tenant, tenant_id)
        if doomed is not None:
            await db.delete(doomed)
            await db.commit()


# --- booking works ----------------------------------------------------------


async def test_booking_an_appointment(client, clinic):
    r = await client.post("/appointments", headers=auth(clinic.admin), json=booking(clinic))
    assert r.status_code == 201
    body = r.json()
    assert body["tenant_id"] == str(clinic.id)
    assert body["status"] == "scheduled"
    assert body["provider_id"] == str(clinic.provider.id)


async def test_the_clinic_comes_from_the_token_not_the_request(client, clinic):
    """Send a different clinic and a finished status. Both must be ignored."""
    payload = booking(clinic) | {
        "tenant_id": str(uuid.uuid4()),
        "status": "completed",
        "id": str(uuid.uuid4()),
    }
    r = await client.post("/appointments", headers=auth(clinic.admin), json=payload)
    assert r.status_code == 201
    assert r.json()["tenant_id"] == str(clinic.id)
    assert r.json()["status"] == "scheduled"
    assert r.json()["id"] != payload["id"]


async def test_booking_needs_a_token(client, clinic):
    assert (await client.post("/appointments", json=booking(clinic))).status_code == 401


@pytest.mark.parametrize(
    "bad,reason",
    [
        ({"scheduled_end": SOON.isoformat()}, "zero length"),
        ({"scheduled_end": (SOON - timedelta(minutes=5)).isoformat()}, "ends first"),
        ({"scheduled_end": (SOON + timedelta(hours=9)).isoformat()}, "nine hours"),
        ({"scheduled_start": "2020-01-01T10:00:00Z",
          "scheduled_end": "2020-01-01T10:30:00Z"}, "in the past"),
        ({"scheduled_start": SOON.replace(tzinfo=None).isoformat()}, "no timezone"),
    ],
)
async def test_nonsense_times_refused(client, clinic, bad, reason):
    r = await client.post("/appointments", headers=auth(clinic.admin), json=booking(clinic) | bad)
    assert r.status_code == 422, reason


# --- one clinic cannot reach another ----------------------------------------


async def test_cannot_book_another_clinics_patient(client, clinic):
    other_id, other_people = await make_second_clinic()
    try:
        payload = booking(clinic) | {"patient_id": str(other_people[UserRole.PATIENT].id)}
        r = await client.post("/appointments", headers=auth(clinic.admin), json=payload)
        assert r.status_code == 404
        assert r.json()["detail"] == "No such patient"
    finally:
        await delete_clinic(other_id)


async def test_cannot_book_another_clinics_doctor(client, clinic):
    other_id, other_people = await make_second_clinic()
    try:
        payload = booking(clinic) | {"provider_id": str(other_people[UserRole.PROVIDER].id)}
        r = await client.post("/appointments", headers=auth(clinic.admin), json=payload)
        assert r.status_code == 404
        assert r.json()["detail"] == "No such provider"
    finally:
        await delete_clinic(other_id)


async def test_another_clinic_gets_404_not_403(client, clinic):
    """The plan's headline check. 403 would confirm the appointment exists."""
    made = await client.post("/appointments", headers=auth(clinic.admin), json=booking(clinic))
    appointment_id = made.json()["id"]

    mine = await client.get(f"/appointments/{appointment_id}", headers=auth(clinic.admin))
    assert mine.status_code == 200

    other_id, other_people = await make_second_clinic()
    try:
        theirs = await client.get(
            f"/appointments/{appointment_id}", headers=auth(other_people[UserRole.ADMIN])
        )
        assert theirs.status_code == 404

        # An id nobody has ever used must look identical to a real one
        # belonging to someone else. Any difference is a way to probe.
        invented = await client.get(
            f"/appointments/{uuid.uuid4()}", headers=auth(other_people[UserRole.ADMIN])
        )
        assert invented.status_code == 404
        assert theirs.json() == invented.json()
    finally:
        await delete_clinic(other_id)


async def test_lists_never_cross_clinics(client, clinic):
    await client.post("/appointments", headers=auth(clinic.admin), json=booking(clinic))
    other_id, other_people = await make_second_clinic()
    try:
        mine = await client.get("/appointments", headers=auth(clinic.admin))
        theirs = await client.get("/appointments", headers=auth(other_people[UserRole.ADMIN]))
        assert len(mine.json()) == 1
        assert theirs.json() == []
    finally:
        await delete_clinic(other_id)


async def test_filters_cannot_widen_the_search(client, clinic):
    """Asking for another clinic's doctor by id still returns nothing."""
    other_id, other_people = await make_second_clinic()
    try:
        await client.post("/appointments", headers=auth(clinic.admin), json=booking(clinic))
        r = await client.get(
            "/appointments",
            headers=auth(other_people[UserRole.ADMIN]),
            params={"provider_id": str(clinic.provider.id)},
        )
        assert r.status_code == 200
        assert r.json() == []
    finally:
        await delete_clinic(other_id)


# --- the same doctor cannot be in two places at once ------------------------


@pytest.mark.parametrize(
    "offset_minutes,length,expected,label",
    [
        (0, 30, 409, "exactly the same slot"),
        (15, 30, 409, "starts halfway through"),
        (-15, 30, 409, "ends halfway through"),
        (-60, 180, 409, "swallows it whole"),
        (30, 30, 201, "starts as the last one ends"),
        (-30, 30, 201, "ends as the next one starts"),
        (120, 30, 201, "hours later"),
    ],
)
async def test_overlapping_bookings(client, clinic, offset_minutes, length, expected, label):
    first = await client.post("/appointments", headers=auth(clinic.admin), json=booking(clinic))
    assert first.status_code == 201, label

    second = await client.post(
        "/appointments",
        headers=auth(clinic.admin),
        json=booking(clinic, SOON + timedelta(minutes=offset_minutes), length),
    )
    assert second.status_code == expected, f"{label}: got {second.status_code}"


async def test_a_clash_is_a_409_not_a_crash(client, clinic):
    await client.post("/appointments", headers=auth(clinic.admin), json=booking(clinic))
    r = await client.post("/appointments", headers=auth(clinic.admin), json=booking(clinic))
    assert r.status_code == 409
    assert "already booked" in r.json()["detail"]


async def test_a_different_doctor_can_take_the_same_hour(client, clinic):
    async with AsyncSessionLocal() as db:
        second_doctor = User(
            tenant_id=clinic.id,
            email=f"doc2@{clinic.slug}.example.com",
            hashed_password="$2b$04$irrelevant",
            full_name="Second Doctor",
            role=UserRole.PROVIDER,
        )
        db.add(second_doctor)
        await db.commit()
        second_id = second_doctor.id

    await client.post("/appointments", headers=auth(clinic.admin), json=booking(clinic))
    r = await client.post(
        "/appointments",
        headers=auth(clinic.admin),
        json=booking(clinic) | {"provider_id": str(second_id)},
    )
    assert r.status_code == 201


# --- the race ---------------------------------------------------------------


class PeakCounter:
    """Counts how many requests are inside the app at the same instant."""

    def __init__(self, app):
        self.app = app
        self.inflight = 0
        self.peak = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        self.inflight += 1
        self.peak = max(self.peak, self.inflight)
        try:
            await self.app(scope, receive, send)
        finally:
            self.inflight -= 1


async def test_ten_simultaneous_bookings_of_one_slot(clinic):
    """Ten requests for the same slot, fired at once. Exactly one may win.

    A sequential test cannot show this. The failure it guards against is two
    requests both checking "is this slot free?", both being told yes, and both
    saving — which only happens when they genuinely overlap in time.

    So the test also proves they overlapped. Without that, ten requests that
    quietly ran one after another would pass just as happily, and the test
    would be worthless while looking fine.
    """
    payload = booking(clinic)
    headers = auth(clinic.admin)

    counter = PeakCounter(app)
    transport = httpx.ASGITransport(app=counter)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        replies = await asyncio.gather(
            *(client.post("/appointments", headers=headers, json=payload) for _ in range(10)),
            return_exceptions=True,
        )

        assert counter.peak == 10, (
            f"only {counter.peak} request(s) were ever in flight together; "
            "this ran sequentially and proves nothing about a race"
        )

        crashed = [r for r in replies if isinstance(r, BaseException)]
        assert not crashed, f"requests raised: {crashed}"

        codes = [r.status_code for r in replies]
        assert codes.count(201) == 1, f"expected exactly one winner, got {codes}"
        assert codes.count(409) == 9, f"expected nine clean refusals, got {codes}"
        assert 500 not in codes, "a clash must never surface as a server error"

        # And the database agrees with the replies.
        listed = await client.get("/appointments", headers=headers)
        assert len(listed.json()) == 1
