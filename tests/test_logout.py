"""Phase 7 — logging out, and tokens that stop working before they expire."""

import uuid

from app.core.redis import create_redis
from app.core.revocation import RevokedTokens, _key
from app.core.tokens import TokenType, create_refresh_token, decode_token
from app.database.models import UserRole


async def login(client, clinic, user=None) -> dict:
    user = user or clinic.admin
    r = await client.post(
        "/auth/login",
        headers={"X-Tenant-Slug": clinic.slug},
        json={"email": user.email, "password": clinic.password},
    )
    assert r.status_code == 200, r.text
    return r.json()


def auth(tokens: dict) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


# --- the flow the plan asks for ---------------------------------------------


async def test_log_in_use_it_log_out_replay_it(client, clinic):
    tokens = await login(client, clinic)

    before = await client.get("/auth/me", headers=auth(tokens))
    assert before.status_code == 200

    out = await client.post("/auth/logout", headers=auth(tokens), json={})
    assert out.status_code == 204

    after = await client.get("/auth/me", headers=auth(tokens))
    assert after.status_code == 401


async def test_logout_kills_every_protected_route_not_just_me(client, clinic):
    tokens = await login(client, clinic)
    await client.post("/auth/logout", headers=auth(tokens), json={})
    assert (await client.get("/appointments", headers=auth(tokens))).status_code == 401


async def test_logging_out_twice_is_harmless(client, clinic):
    tokens = await login(client, clinic)
    assert (await client.post("/auth/logout", headers=auth(tokens), json={})).status_code == 204
    # The second attempt now carries a revoked token, so it is refused as any
    # other revoked token would be — not treated as an error worth reporting.
    assert (await client.post("/auth/logout", headers=auth(tokens), json={})).status_code == 401


async def test_logout_needs_a_working_token(client, clinic):
    """Otherwise anyone could stuff the revocation list with invented ids."""
    bad = {"Authorization": "Bearer not-a-real-token"}
    assert (await client.post("/auth/logout", headers=bad, json={})).status_code == 401
    assert (await client.post("/auth/logout", json={})).status_code == 401


# --- other sessions are left alone ------------------------------------------


async def test_logging_out_on_one_device_leaves_the_other_alone(client, clinic):
    phone = await login(client, clinic)
    laptop = await login(client, clinic)

    await client.post("/auth/logout", headers=auth(phone), json={})

    assert (await client.get("/auth/me", headers=auth(phone))).status_code == 401
    assert (await client.get("/auth/me", headers=auth(laptop))).status_code == 200


async def test_one_persons_logout_does_not_touch_anyone_else(client, clinic):
    mine = await login(client, clinic, clinic.admin)
    theirs = await login(client, clinic, clinic.patient)

    await client.post("/auth/logout", headers=auth(mine), json={})

    assert (await client.get("/auth/me", headers=auth(mine))).status_code == 401
    assert (await client.get("/auth/me", headers=auth(theirs))).status_code == 200


# --- the refresh token --------------------------------------------------------


async def test_handing_in_the_refresh_token_cancels_it_too(client, clinic):
    """Without this, logging out would be cosmetic once /auth/refresh exists.

    The week-long token would survive, and the very next request for a fresh
    pass would hand one out moments after logging out.
    """
    tokens = await login(client, clinic)
    refresh_claims = decode_token(tokens["refresh_token"], expected_type=TokenType.REFRESH)

    out = await client.post(
        "/auth/logout",
        headers=auth(tokens),
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert out.status_code == 204

    redis = create_redis()
    try:
        assert await RevokedTokens(redis).is_revoked(refresh_claims.jti)
    finally:
        await redis.aclose()


async def test_cannot_cancel_somebody_elses_refresh_token(client, clinic):
    """Handing in a stranger's refresh token must not log them out."""
    victim = create_refresh_token(
        user_id=clinic.patient.id, tenant_id=clinic.id, role=UserRole.PATIENT
    )
    attacker = await login(client, clinic, clinic.admin)

    out = await client.post(
        "/auth/logout", headers=auth(attacker), json={"refresh_token": victim.token}
    )
    assert out.status_code == 204  # the attacker's own logout still works

    redis = create_redis()
    try:
        assert not await RevokedTokens(redis).is_revoked(victim.jti)
    finally:
        await redis.aclose()


async def test_a_rubbish_refresh_token_does_not_fail_the_logout(client, clinic):
    tokens = await login(client, clinic)
    out = await client.post(
        "/auth/logout", headers=auth(tokens), json={"refresh_token": "nonsense"}
    )
    assert out.status_code == 204
    assert (await client.get("/auth/me", headers=auth(tokens))).status_code == 401


# --- the list looks after itself --------------------------------------------


async def test_the_entry_expires_with_the_token(client, clinic):
    """Remembered for exactly as long as the token had left, no longer.

    After that the token is refused for being stale anyway, so keeping the
    entry would only fill Redis with things that no longer matter.
    """
    tokens = await login(client, clinic)
    claims = decode_token(tokens["access_token"], expected_type=TokenType.ACCESS)
    await client.post("/auth/logout", headers=auth(tokens), json={})

    redis = create_redis()
    try:
        ttl = await redis.ttl(_key(claims.jti))
        assert 0 < ttl <= 900, f"expected up to 15 minutes, got {ttl}s"
    finally:
        await redis.aclose()


async def test_a_token_nobody_revoked_is_not_in_the_list(client, clinic):
    tokens = await login(client, clinic)
    claims = decode_token(tokens["access_token"], expected_type=TokenType.ACCESS)
    redis = create_redis()
    try:
        assert not await RevokedTokens(redis).is_revoked(claims.jti)
        assert not await RevokedTokens(redis).is_revoked(uuid.uuid4())
    finally:
        await redis.aclose()
