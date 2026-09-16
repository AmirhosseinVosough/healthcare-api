"""Works out who is making a request, from the token they present."""

import uuid
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.database.models import User, UserRole

# auto_error=False matters. Left to itself, FastAPI answers a missing
# Authorization header with 403, which means "I know who you are and you are
# not allowed". The honest answer is 401, "I do not know who you are" — so we
# turn its handling off and raise the right one below.
#
# Declaring this scheme is also what puts the Authorize button in /docs: log in
# at /auth/login, copy the access token, paste it once, and every protected
# route on the page becomes clickable.
bearer_scheme = HTTPBearer(
    auto_error=False,
    description="Paste the access_token returned by /auth/login",
)


def not_authenticated() -> HTTPException:
    """One answer for every unusable token, with no hint as to which fault."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_bearer_token(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(bearer_scheme)
    ],
) -> str:
    """The raw token string, or 401.

    Nothing here says whether the token is any good — that is step 3's job.
    This only gets it out of the envelope.
    """
    if credentials is None or not credentials.credentials.strip():
        raise not_authenticated()
    return credentials.credentials


@dataclass(frozen=True, slots=True)
class CurrentUser:
    """Who is making this request. A plain snapshot, not the database row.

    Three reasons this is not just the User object:

    A User is tied to the database session that loaded it. Once that session
    closes, touching an attribute can fire another query or fail outright. This
    is inert — it works anywhere, including after everything is closed.

    A User carries hashed_password. Return one from a route by accident and the
    hash goes out over the wire. There is no such field here to leak.

    Frozen, so a route cannot quietly reassign tenant_id to something else and
    have the rest of the request believe it.
    """

    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    full_name: str
    role: UserRole

    @classmethod
    def from_user(cls, user: User) -> "CurrentUser":
        return cls(
            id=user.id,
            tenant_id=user.tenant_id,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
        )

    @property
    def is_admin(self) -> bool:
        return self.role is UserRole.ADMIN

    @property
    def is_provider(self) -> bool:
        return self.role is UserRole.PROVIDER

    @property
    def is_patient(self) -> bool:
        return self.role is UserRole.PATIENT
