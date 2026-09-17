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


# --- the tests above all use caplog, which is why they missed this ----------
#
# caplog attaches its own handler and lowers the level, so it captures records
# at the logger — before anything decides whether to emit them. Every test
# above passed while the audit trail produced no output at all in a real
# server. These check what actually comes out.


def test_the_audit_logger_has_somewhere_to_write(capsys):
    """Without a handler, INFO records are dropped in silence."""
    import logging

    from app.core.logging import configure_logging

    configure_logging()
    logger = logging.getLogger("audit")
    assert logger.handlers, "no handler: audit lines go nowhere"
    assert logger.level <= logging.INFO
    assert not logger.propagate, "would emit twice once a root handler exists"


def test_an_audit_line_reaches_standard_output(capsys):
    """End to end: call record(), read stdout."""
    import uuid

    from app.core import audit
    from app.core.logging import configure_logging

    configure_logging()
    tenant, user = uuid.uuid4(), uuid.uuid4()
    audit.record(
        action="appointment.read",
        tenant_id=tenant,
        user_id=user,
        request_id="req-abc",
        resource_id=uuid.uuid4(),
    )

    written = capsys.readouterr().out
    assert written.strip(), "nothing was written to stdout"
    entry = json.loads(written.strip().splitlines()[-1])
    assert entry["action"] == "appointment.read"
    assert entry["tenant_id"] == str(tenant)
    assert entry["request_id"] == "req-abc"


def test_the_line_is_json_and_nothing_else(capsys):
    """No timestamp or level prefix, or downstream has to strip it first."""
    import uuid

    from app.core import audit
    from app.core.logging import configure_logging

    configure_logging()
    audit.record(
        action="appointment.list",
        tenant_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        request_id="req-xyz",
    )
    line = capsys.readouterr().out.strip().splitlines()[-1]
    assert line.startswith("{") and line.endswith("}")
    json.loads(line)  # raises if the line is not pure JSON
