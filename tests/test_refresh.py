"""Phase 8 — trading a refresh token for a new pair, and burning the old one."""

from app.core.tokens import TokenType, decode_token


async def login(client, clinic) -> dict:
    r = await client.post(
        "/auth/login",
        headers={"X-Tenant-Slug": clinic.slug},
        json={"email": clinic.admin.email, "password": clinic.password},
    )
    assert r.status_code == 200
    return r.json()


def auth(tokens: dict) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def test_refreshing_gives_a_working_new_token(client, clinic):
    old = await login(client, clinic)
    r = await client.post("/auth/refresh", json={"refresh_token": old["refresh_token"]})
    assert r.status_code == 200
    new = r.json()
    assert new["access_token"] != old["access_token"]
    assert (await client.get("/auth/me", headers=auth(new))).status_code == 200


async def test_the_old_refresh_token_stops_working(client, clinic):
    """Rotation. A copy of the old one is worthless the moment it is used."""
    old = await login(client, clinic)
    first = await client.post(
        "/auth/refresh", json={"refresh_token": old["refresh_token"]}
    )
    assert first.status_code == 200

    again = await client.post(
        "/auth/refresh", json={"refresh_token": old["refresh_token"]}
    )
    assert again.status_code == 401


async def test_each_refresh_hands_out_a_fresh_pair(client, clinic):
    tokens = await login(client, clinic)
    seen = set()
    for _ in range(3):
        r = await client.post(
            "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        assert r.status_code == 200
        tokens = r.json()
        jti = decode_token(tokens["refresh_token"], expected_type=TokenType.REFRESH).jti
        assert jti not in seen
        seen.add(jti)


async def test_an_access_token_cannot_be_used_to_refresh(client, clinic):
    tokens = await login(client, clinic)
    r = await client.post("/auth/refresh", json={"refresh_token": tokens["access_token"]})
    assert r.status_code == 401


async def test_rubbish_is_refused(client, clinic):
    for bad in ("", "not-a-token", "a.b.c"):
        r = await client.post("/auth/refresh", json={"refresh_token": bad})
        assert r.status_code in (401, 422), bad


async def test_logging_out_kills_the_refresh_token(client, clinic):
    """The two halves of Phase 7 and Phase 8 have to agree with each other."""
    tokens = await login(client, clinic)
    out = await client.post(
        "/auth/logout",
        headers=auth(tokens),
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert out.status_code == 204

    r = await client.post(
        "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert r.status_code == 401, "logging out left the week-long token alive"


async def test_refreshing_is_rate_limited(client, clinic):
    tokens = await login(client, clinic)
    codes = []
    for _ in range(6):
        r = await client.post(
            "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        codes.append(r.status_code)
        if r.status_code == 200:
            tokens = r.json()
    assert 429 in codes, f"refresh should be limited too: {codes}"
