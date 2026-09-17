"""Request and response shapes for the auth endpoints.

Kept deliberately separate from the database models. A request model can only
carry the fields listed here, so a caller cannot smuggle in `role: admin` or a
clinic id that isn't theirs by adding it to the JSON. A response model can only
emit the fields listed here, so a password hash cannot leak by accident.
"""

import uuid
from typing import Annotated

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.core.security import MAX_PASSWORD_BYTES
from app.database.models import UserRole

# 8 characters minimum; the upper bound is bcrypt's, which ignores anything
# past 72 bytes. Checked in bytes below, because a character can be several.
Password = Annotated[str, Field(min_length=8, max_length=MAX_PASSWORD_BYTES)]

# Lowercase words joined by single hyphens: "riverside-clinic".
Slug = Annotated[
    str, Field(min_length=3, max_length=64, pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$")
]


class _PasswordCarrier(BaseModel):
    """Shared byte-length check for every model that accepts a password."""

    @field_validator("password", check_fields=False)
    @classmethod
    def _within_bcrypt_limit(cls, value: str) -> str:
        size = len(value.encode("utf-8"))
        if size > MAX_PASSWORD_BYTES:
            raise ValueError(
                f"password is {size} bytes; the limit is {MAX_PASSWORD_BYTES}. "
                "Emoji and accented letters count as more than one byte each."
            )
        return value


class _EmailCarrier(BaseModel):
    """Emails are stored lowercase so Sarah@x.com and sarah@x.com are one account."""

    @field_validator("email", check_fields=False)
    @classmethod
    def _normalise(cls, value: str) -> str:
        return value.strip().lower()


class ClinicSignupRequest(_PasswordCarrier, _EmailCarrier):
    """Creates a brand new clinic and the person who will run it."""

    clinic_name: Annotated[str, Field(min_length=2, max_length=200)]
    clinic_slug: Slug
    full_name: Annotated[str, Field(min_length=1, max_length=200)]
    email: EmailStr
    password: Password


class PatientRegisterRequest(_PasswordCarrier, _EmailCarrier):
    """Joins an existing clinic. The clinic comes from the X-Tenant-Slug header.

    There is deliberately no `role` field: the endpoint hardcodes patient, so
    adding "role": "admin" to the JSON does nothing at all.
    """

    full_name: Annotated[str, Field(min_length=1, max_length=200)]
    email: EmailStr
    password: Password


class LoginRequest(_EmailCarrier):
    email: EmailStr
    password: str  # no length rules: a wrong password is a 401, not a 422


class ClinicOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str


class UserOut(BaseModel):
    """Note what is absent: hashed_password. It cannot leak from here."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    email: EmailStr
    full_name: str
    role: UserRole


class ClinicSignupResponse(BaseModel):
    clinic: ClinicOut
    admin: UserOut


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access_token dies, for the client's timer


class LogoutRequest(BaseModel):
    """The refresh token is optional but strongly wanted.

    Without it, logging out only cancels the fifteen-minute token while the
    week-long one stays live, and the next request for a fresh token hands
    out a new pass moments later — which makes logging out look like it
    worked while changing nothing.
    """

    refresh_token: str | None = None


class RefreshRequest(BaseModel):
    refresh_token: str
