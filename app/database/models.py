import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    literal_column,
    text,
)
from sqlalchemy.dialects.postgresql import ExcludeConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Explicit naming convention so Alembic autogenerate emits stable, human-readable
# constraint names instead of database-assigned ones.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    PROVIDER = "provider"
    PATIENT = "patient"


class AppointmentStatus(str, enum.Enum):
    SCHEDULED = "scheduled"
    CONFIRMED = "confirmed"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    NO_SHOW = "no_show"


def _pg_enum(py_enum: type[enum.Enum], name: str) -> Enum:
    """Store the enum *values* in Postgres, not the Python member names."""
    return Enum(py_enum, name=name, values_callable=lambda e: [m.value for m in e])


class Tenant(Base):
    """A clinic. The isolation boundary every other row hangs off."""

    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        # Email is unique *within* a clinic: the same person may be a patient at
        # two different clinics, and those are separate accounts.
        UniqueConstraint("tenant_id", "email", name="uq_users_tenant_id_email"),
        # Target for the composite foreign keys on appointments below, which is
        # what makes a cross-tenant reference impossible at the database level.
        UniqueConstraint("id", "tenant_id", name="uq_users_id_tenant_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    email: Mapped[str] = mapped_column(String(320))
    hashed_password: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[str] = mapped_column(String(200))
    role: Mapped[UserRole] = mapped_column(_pg_enum(UserRole, "user_role"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Appointment(Base):
    __tablename__ = "appointments"
    __table_args__ = (
        # Composite FKs carrying tenant_id: the patient and the provider must
        # belong to the same tenant as the appointment, enforced by Postgres
        # rather than by remembering to write the right WHERE clause.
        ForeignKeyConstraint(
            ["patient_id", "tenant_id"],
            ["users.id", "users.tenant_id"],
            ondelete="CASCADE",
            name="fk_appointments_patient_users",
        ),
        ForeignKeyConstraint(
            ["provider_id", "tenant_id"],
            ["users.id", "users.tenant_id"],
            ondelete="RESTRICT",
            name="fk_appointments_provider_users",
        ),
        CheckConstraint("scheduled_end > scheduled_start", name="end_after_start"),
        # The same doctor cannot be in two places at once. Postgres refuses any
        # appointment whose time range overlaps an existing one for that
        # provider, so two requests arriving in the same instant cannot both
        # win — the database decides, not a check in our code that another
        # request can slip past.
        #
        # Cancelled appointments are left out: cancelling should free the slot.
        ExcludeConstraint(
            ("tenant_id", "="),
            ("provider_id", "="),
            (literal_column("tstzrange(scheduled_start, scheduled_end)"), "&&"),
            name="no_provider_double_booking",
            using="gist",
            where=text("status <> 'cancelled'"),
        ),
        Index(
            "ix_appointments_tenant_id_scheduled_start", "tenant_id", "scheduled_start"
        ),
        Index(
            "ix_appointments_tenant_id_provider_id_scheduled_start",
            "tenant_id",
            "provider_id",
            "scheduled_start",
        ),
        Index("ix_appointments_tenant_id_patient_id", "tenant_id", "patient_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("tenants.id", ondelete="CASCADE")
    )
    patient_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    provider_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    scheduled_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    scheduled_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[AppointmentStatus] = mapped_column(
        _pg_enum(AppointmentStatus, "appointment_status"),
        default=AppointmentStatus.SCHEDULED,
        server_default=AppointmentStatus.SCHEDULED.value,
    )
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # viewonly + lazy="raise": writes always go through the explicit *_id columns,
    # and an accidental lazy load fails loudly instead of blowing up the event loop.
    patient: Mapped["User"] = relationship(
        "User",
        primaryjoin="and_(Appointment.patient_id == User.id, "
        "Appointment.tenant_id == User.tenant_id)",
        viewonly=True,
        lazy="raise",
    )
    provider: Mapped["User"] = relationship(
        "User",
        primaryjoin="and_(Appointment.provider_id == User.id, "
        "Appointment.tenant_id == User.tenant_id)",
        viewonly=True,
        lazy="raise",
    )
