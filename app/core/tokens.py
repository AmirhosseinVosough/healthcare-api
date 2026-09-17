"""Minting and reading JSON Web Tokens.

The clinic id travels in the signed payload as `tid`. That is the whole
point: every later request reads the caller's clinic from a token the
server signed, never from a header, query string or body the caller can
edit. A signed claim can be forged only by forging the signature.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum

import jwt
from pydantic import BaseModel, ValidationError

from app.core.config import settings
from app.database.models import UserRole


class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"


class TokenError(Exception):
    """Any reason a token was not accepted. Carries no detail for the client."""


class TokenClaims(BaseModel):
    sub: uuid.UUID  # the user
    tid: uuid.UUID  # the clinic
    role: UserRole
    jti: uuid.UUID  # this token's own id, so it can be revoked one at a time
    typ: TokenType  # payload claim, unrelated to the JOSE header of the same name
    iat: datetime
    exp: datetime


@dataclass(frozen=True)
class IssuedToken:
    token: str
    jti: uuid.UUID
    expires_at: datetime


def _create_token(
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    role: UserRole,
    token_type: TokenType,
    lifetime: timedelta,
) -> IssuedToken:
    now = datetime.now(UTC)
    expires_at = now + lifetime
    jti = uuid.uuid4()
    payload = {
        # str(), not UUID: the JWT spec says `sub` is a string, and PyJWT
        # rejects anything else on the way back in.
        "sub": str(user_id),
        "tid": str(tenant_id),
        "role": role.value,
        "jti": str(jti),
        "typ": token_type.value,
        "iat": now,
        "exp": expires_at,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return IssuedToken(token=token, jti=jti, expires_at=expires_at)


def create_access_token(
    *, user_id: uuid.UUID, tenant_id: uuid.UUID, role: UserRole
) -> IssuedToken:
    """Short-lived token sent on every request. 15 minutes by default."""
    return _create_token(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        token_type=TokenType.ACCESS,
        lifetime=timedelta(minutes=settings.access_token_expire_minutes),
    )


def create_refresh_token(
    *, user_id: uuid.UUID, tenant_id: uuid.UUID, role: UserRole
) -> IssuedToken:
    """Long-lived token whose only job is to obtain a new access token."""
    return _create_token(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        token_type=TokenType.REFRESH,
        lifetime=timedelta(days=settings.refresh_token_expire_days),
    )


def decode_token(token: str, *, expected_type: TokenType) -> TokenClaims:
    """Verify a token and return its claims, or raise TokenError.

    Raises rather than returning None so a caller cannot forget to check.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            # Pinned to our own algorithm. Trusting the `alg` header instead
            # is the classic JWT hole: an attacker sets alg to "none", drops
            # the signature, and walks in as anyone.
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "iat", "sub", "jti"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("token is not valid") from exc

    try:
        claims = TokenClaims.model_validate(payload)
    except ValidationError as exc:
        raise TokenError("token claims are malformed") from exc

    # Checked only after the signature holds, so this never leaks anything
    # about a token we haven't authenticated. A refresh token must not be
    # usable as an access token: it lives for a week rather than 15 minutes.
    if claims.typ is not expected_type:
        raise TokenError(f"expected token type {expected_type.value}")

    return claims
