"""Request and response shapes for appointments.

The booking request carries no tenant_id. The clinic comes from the caller's
token and nowhere else, so there is no field to tamper with even in principle.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.database.models import AppointmentStatus

MAX_APPOINTMENT_LENGTH = timedelta(hours=8)


class AppointmentCreate(BaseModel):
    """What a caller may ask for.

    Note what is missing: tenant_id, status, id, created_at. A booking is
    always made in the caller's own clinic, always starts as scheduled, and
    gets its id from us.
    """

    patient_id: uuid.UUID
    provider_id: uuid.UUID
    scheduled_start: datetime
    scheduled_end: datetime
    reason: Annotated[str | None, Field(default=None, max_length=2000)]

    @model_validator(mode="after")
    def _check_the_times_make_sense(self) -> "AppointmentCreate":
        if self.scheduled_start.tzinfo is None or self.scheduled_end.tzinfo is None:
            raise ValueError(
                "times must say which timezone they are in, e.g. "
                "2026-10-01T10:00:00Z"
            )
        if self.scheduled_end <= self.scheduled_start:
            raise ValueError("the appointment must end after it starts")
        if self.scheduled_end - self.scheduled_start > MAX_APPOINTMENT_LENGTH:
            raise ValueError("an appointment cannot run longer than 8 hours")
        if self.scheduled_start < datetime.now(timezone.utc):
            raise ValueError("cannot book an appointment in the past")
        return self


class AppointmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    patient_id: uuid.UUID
    provider_id: uuid.UUID
    scheduled_start: datetime
    scheduled_end: datetime
    status: AppointmentStatus
    reason: str | None
    created_at: datetime
