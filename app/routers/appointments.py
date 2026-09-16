"""Appointments, always scoped to the caller's own clinic."""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Appointment, AppointmentStatus, User, UserRole
from app.database.session import get_db
from app.dependencies.auth import CurrentUser, get_current_user
from app.schemas.appointment import AppointmentCreate, AppointmentOut

router = APIRouter(prefix="/appointments", tags=["appointments"])

DbSession = Annotated[AsyncSession, Depends(get_db)]
Caller = Annotated[CurrentUser, Depends(get_current_user)]

# Postgres names for the two things that can go wrong on insert.
SLOT_TAKEN = "no_provider_double_booking"


async def _person_in_this_clinic(
    db: AsyncSession, person_id: uuid.UUID, tenant_id: uuid.UUID, role: UserRole
) -> User | None:
    """Look someone up inside one clinic only.

    Matching on tenant_id here means a patient or doctor id belonging to
    another clinic simply is not found, so the error says "no such patient"
    rather than "that patient is not yours" — which would confirm they exist.
    """
    return await db.scalar(
        select(User).where(
            User.id == person_id,
            User.tenant_id == tenant_id,
            User.role == role,
            User.is_active.is_(True),
        )
    )


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=AppointmentOut,
    summary="Book an appointment",
)
async def create_appointment(
    payload: AppointmentCreate, caller: Caller, db: DbSession
):
    patient = await _person_in_this_clinic(
        db, payload.patient_id, caller.tenant_id, UserRole.PATIENT
    )
    if patient is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="No such patient"
        )

    provider = await _person_in_this_clinic(
        db, payload.provider_id, caller.tenant_id, UserRole.PROVIDER
    )
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="No such provider"
        )

    appointment = Appointment(
        # The clinic comes from the token. There is no field on the request
        # that could have set it, and none that could override it here.
        tenant_id=caller.tenant_id,
        patient_id=payload.patient_id,
        provider_id=payload.provider_id,
        scheduled_start=payload.scheduled_start,
        scheduled_end=payload.scheduled_end,
        reason=payload.reason,
        status=AppointmentStatus.SCHEDULED,
    )
    db.add(appointment)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        # Two requests can pass the checks above at the same instant and both
        # reach this point. Only one gets past the database, and the loser
        # gets a clean 409 rather than a 500.
        if SLOT_TAKEN in str(exc.orig):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="That provider is already booked for part of that time",
            ) from None
        raise

    return AppointmentOut.model_validate(appointment)


@router.get(
    "",
    response_model=list[AppointmentOut],
    summary="List appointments in your clinic",
)
async def list_appointments(
    caller: Caller,
    db: DbSession,
    provider_id: Annotated[uuid.UUID | None, Query()] = None,
    patient_id: Annotated[uuid.UUID | None, Query()] = None,
    appointment_status: Annotated[AppointmentStatus | None, Query(alias="status")] = None,
    starts_after: Annotated[datetime | None, Query()] = None,
    starts_before: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Every filter below narrows within the caller's clinic. None widens it.

    The tenant_id condition is the first thing on the query and is not
    reachable from any parameter, so no combination of filters can escape it.
    """
    query = select(Appointment).where(Appointment.tenant_id == caller.tenant_id)

    if provider_id is not None:
        query = query.where(Appointment.provider_id == provider_id)
    if patient_id is not None:
        query = query.where(Appointment.patient_id == patient_id)
    if appointment_status is not None:
        query = query.where(Appointment.status == appointment_status)
    if starts_after is not None:
        query = query.where(Appointment.scheduled_start >= starts_after)
    if starts_before is not None:
        query = query.where(Appointment.scheduled_start < starts_before)

    query = query.order_by(Appointment.scheduled_start).limit(limit).offset(offset)
    rows = (await db.scalars(query)).all()
    return [AppointmentOut.model_validate(r) for r in rows]
