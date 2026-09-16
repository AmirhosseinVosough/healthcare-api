"""Works out who is making a request, from the token they present."""

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

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
