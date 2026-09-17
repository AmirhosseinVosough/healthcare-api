"""Phase 8 — every read and write of patient data leaves a trail."""

import json
import logging
from datetime import UTC, datetime, timedelta

import pytest

from app.core.tokens import create_access_token

SOON = datetime.now(UTC) + timedelta(days=45)


@pytest.fixture
def audit_lines(caplog):
    caplog.set_level(logging.INFO, logger="audit")

    def read() -> list[dict]:
        return [json.loads(r.message) for r in caplog.records if r.name == "audit"]

    return read


def auth(clinic, who="admin"):
    person = getattr(clinic, who)
    token = create_access_token(
        user_id=person.id, tenant_id=clinic.id, role=person.role
    ).token
    return {"Authorization": f"Bearer {token}"}


def booking(clinic):
    return {
        "patient_id": str(clinic.patient.id),
        "provider_id": str(clinic.provider.id),
        "scheduled_start": SOON.isoformat(),
        "scheduled_end": (SOON + timedelta(minutes=30)).isoformat(),
    }


async def test_booking_is_recorded(client, clinic, audit_lines):
    r = await client.post("/appointments", headers=auth(clinic), json=booking(clinic))
    assert r.status_code == 201

    written = [line for line in audit_lines() if line["action"] == "appointment.create"]
    assert len(written) == 1
    entry = written[0]
    assert entry["tenant_id"] == str(clinic.id)
    assert entry["user_id"] == str(clinic.admin.id)
    assert entry["resource_id"] == r.json()["id"]
    assert entry["outcome"] == "ok"
    assert entry["request_id"]


async def test_reading_is_recorded_too(client, clinic, audit_lines):
    """Who looked matters as much as who changed something."""
    made = await client.post("/appointments", headers=auth(clinic), json=booking(clinic))
    await client.get(f"/appointments/{made.json()['id']}", headers=auth(clinic))

    reads = [line for line in audit_lines() if line["action"] == "appointment.read"]
    assert len(reads) == 1
    assert reads[0]["resource_id"] == made.json()["id"]


async def test_a_miss_is_recorded(client, clinic, audit_lines):
    """A run of these from one account is somebody guessing ids."""
    import uuid

    await client.get(f"/appointments/{uuid.uuid4()}", headers=auth(clinic))
    misses = [
        line
        for line in audit_lines()
        if line["action"] == "appointment.read" and line["outcome"] == "not_found"
    ]
    assert len(misses) == 1


async def test_listing_records_how_many_came_back(client, clinic, audit_lines):
    await client.post("/appointments", headers=auth(clinic), json=booking(clinic))
    await client.get("/appointments", headers=auth(clinic))

    lists = [line for line in audit_lines() if line["action"] == "appointment.list"]
    assert lists[-1]["returned"] == "1"


async def test_the_trail_never_copies_the_sensitive_parts(client, clinic, audit_lines):
    """Ids only. A log that repeats the notes has doubled where they live."""
    payload = booking(clinic) | {"reason": "Suspected fracture, left wrist"}
    await client.post("/appointments", headers=auth(clinic), json=payload)

    everything = json.dumps(audit_lines())
    assert "fracture" not in everything
    assert clinic.patient.email not in everything
    assert clinic.patient.full_name not in everything


async def test_one_request_one_id(client, clinic, audit_lines):
    r = await client.post("/appointments", headers=auth(clinic), json=booking(clinic))
    assert r.headers["X-Request-ID"]
    entry = [line for line in audit_lines() if line["action"] == "appointment.create"][0]
    assert entry["request_id"] == r.headers["X-Request-ID"]


async def test_an_incoming_request_id_is_kept(client, clinic, audit_lines):
    """So one user action can be followed across services, not just ours."""
    given = "from-the-load-balancer-123"
    r = await client.post(
        "/appointments",
        headers=auth(clinic) | {"X-Request-ID": given},
        json=booking(clinic),
    )
    assert r.headers["X-Request-ID"] == given
    entry = [line for line in audit_lines() if line["action"] == "appointment.create"][0]
    assert entry["request_id"] == given
