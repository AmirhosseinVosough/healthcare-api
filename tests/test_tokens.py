"""Phase 2 — JWT minting and verification. No database, no HTTP."""

import uuid
import warnings
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.core.config import settings
from app.core.tokens import (
    TokenError,
    TokenType,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.database.models import UserRole

USER_ID = uuid.uuid4()
CLINIC_ID = uuid.uuid4()


@pytest.fixture
def access():
    return create_access_token(
        user_id=USER_ID, tenant_id=CLINIC_ID, role=UserRole.PROVIDER
    )


@pytest.fixture
def refresh():
    return create_refresh_token(
        user_id=USER_ID, tenant_id=CLINIC_ID, role=UserRole.PATIENT
    )


def forge(*, key=None, algorithm="HS256", **overrides) -> str:
    """Build a token an attacker might present. Signed with our key by default."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(USER_ID),
        "tid": str(CLINIC_ID),
        "role": "admin",
        "jti": str(uuid.uuid4()),
        "typ": "access",
        "iat": now,
        "exp": now + timedelta(minutes=15),
    }
    payload.update(overrides)
    payload = {k: v for k, v in payload.items() if v is not None}
    return jwt.encode(
        payload,
        settings.jwt_secret if key is None else key,
        algorithm=algorithm,
    )


# --- the happy path ---------------------------------------------------------


def test_access_token_round_trips(access):
    claims = decode_token(access.token, expected_type=TokenType.ACCESS)
    assert claims.sub == USER_ID
    assert claims.tid == CLINIC_ID
    assert claims.role is UserRole.PROVIDER


def test_clinic_id_really_travels_inside_the_signed_payload(access):
    """The isolation story depends on this claim being in the token itself."""
    unverified = jwt.decode(access.token, options={"verify_signature": False})
    assert unverified["tid"] == str(CLINIC_ID)


def test_issued_jti_matches_the_claim(access):
    """The caller stores this id to revoke exactly one token later."""
    claims = decode_token(access.token, expected_type=TokenType.ACCESS)
    assert claims.jti == access.jti


def test_every_token_gets_its_own_jti(access):
    other = create_access_token(
        user_id=USER_ID, tenant_id=CLINIC_ID, role=UserRole.PROVIDER
    )
    assert other.jti != access.jti


def test_refresh_token_outlives_the_access_token(access, refresh):
    gap = (refresh.expires_at - access.expires_at).total_seconds()
    expected = (
        timedelta(days=settings.refresh_token_expire_days)
        - timedelta(minutes=settings.access_token_expire_minutes)
    ).total_seconds()
    assert gap == pytest.approx(expected, abs=5)


def test_signing_key_is_long_enough_for_the_algorithm():
    """PyJWT warns below 32 bytes for HS256; a guessable key forges any clinic."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        create_access_token(
            user_id=USER_ID, tenant_id=CLINIC_ID, role=UserRole.ADMIN
        )


# --- everything that must be refused ----------------------------------------


def test_refresh_token_refused_where_access_expected(refresh):
    with pytest.raises(TokenError):
        decode_token(refresh.token, expected_type=TokenType.ACCESS)


def test_access_token_refused_where_refresh_expected(access):
    with pytest.raises(TokenError):
        decode_token(access.token, expected_type=TokenType.REFRESH)


def test_tampered_signature_refused(access):
    tail = "aaaa" if not access.token.endswith("aaaa") else "bbbb"
    with pytest.raises(TokenError):
        decode_token(access.token[:-4] + tail, expected_type=TokenType.ACCESS)


def test_token_signed_with_another_key_refused():
    with pytest.raises(TokenError):
        decode_token(
            forge(key="a" * 40 + "-not-our-secret"), expected_type=TokenType.ACCESS
        )


def test_expired_token_refused():
    now = datetime.now(timezone.utc)
    stale = forge(iat=now - timedelta(hours=2), exp=now - timedelta(hours=1))
    with pytest.raises(TokenError):
        decode_token(stale, expected_type=TokenType.ACCESS)


def test_unsigned_alg_none_token_refused():
    """The classic JWT hole: declare the token unsigned and hope nobody checks."""
    with pytest.raises(TokenError):
        decode_token(forge(key="", algorithm="none"), expected_type=TokenType.ACCESS)


@pytest.mark.parametrize("missing", ["exp", "iat", "sub", "jti", "tid"])
def test_token_missing_a_required_claim_refused(missing):
    with pytest.raises(TokenError):
        decode_token(forge(**{missing: None}), expected_type=TokenType.ACCESS)


def test_invented_role_refused():
    with pytest.raises(TokenError):
        decode_token(forge(role="superuser"), expected_type=TokenType.ACCESS)


def test_non_uuid_clinic_id_refused():
    with pytest.raises(TokenError):
        decode_token(forge(tid="' OR 1=1 --"), expected_type=TokenType.ACCESS)


@pytest.mark.parametrize("garbage", ["", "not-a-token", "a.b.c", "Bearer xyz"])
def test_garbage_refused_without_crashing(garbage):
    with pytest.raises(TokenError):
        decode_token(garbage, expected_type=TokenType.ACCESS)
