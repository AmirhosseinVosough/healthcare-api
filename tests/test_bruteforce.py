"""The two guards on the login door, and the spoofing hole they close.

Guard 1: per-caller address limit. The header that names the caller is only
believed when the connection came from a trusted proxy.

Guard 2: per-account failed-login limit. Only failures count, and a correct
password is honoured even when the account's budget is full.
"""

import uuid
from types import SimpleNamespace

import pytest

from app.core.config import settings
from app.core.rate_limit import RateLimiter
from app.core.redis import create_redis
from app.dependencies.rate_limit import caller_address


def fake_request(peer: str, forwarded: str | None = None):
    headers = {}
    if forwarded is not None:
        headers["X-Forwarded-For"] = forwarded
    return SimpleNamespace(
        client=SimpleNamespace(host=peer),
        headers={k.lower(): v for k, v in headers.items()}
        | {"X-Forwarded-For": forwarded}
        if forwarded is not None
        else {},
    )


# --- Guard 1: the address the caller cannot fake ----------------------------


def test_forwarded_header_is_ignored_from_an_untrusted_peer(monkeypatch):
    """The hole. A caller inventing X-Forwarded-For must not be believed."""
    monkeypatch.setattr(settings, "trusted_proxy_ips", "")  # trust nobody
    req = fake_request(peer="203.0.113.9", forwarded="1.2.3.4")
    # We use the real connection, not the header the caller wrote.
    assert caller_address(req) == "203.0.113.9"


def test_forwarded_header_is_believed_from_a_trusted_proxy(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_ips", "10.0.0.1")
    req = fake_request(peer="10.0.0.1", forwarded="1.2.3.4")
    assert caller_address(req) == "1.2.3.4"


def test_only_the_proxy_added_hop_is_trusted(monkeypatch):
    """A caller who pre-loads the header still cannot choose their address.

    The proxy appends the real client on the right. Anything to the left of
    that is whatever the caller sent, so it is ignored.
    """
    monkeypatch.setattr(settings, "trusted_proxy_ips", "10.0.0.1")
    # Attacker sent "1.2.3.4"; our proxy appended the true client "9.9.9.9".
    req = fake_request(peer="10.0.0.1", forwarded="1.2.3.4, 9.9.9.9")
    assert caller_address(req) == "9.9.9.9"


# --- Guard 2: per account, failures only ------------------------------------


@pytest.fixture
async def redis():
    client = create_redis()
    yield client
    await client.aclose()


@pytest.fixture
def trust_the_test_client(client, monkeypatch):
    """Treat the test client as a trusted proxy, so X-Forwarded-For is believed.

    That lets each request below claim a different source address, which is how
    a real attack on one account looks — many machines, one target — and the
    only way to exercise the per-account guard without the per-address guard
    stopping us at five.
    """
    monkeypatch.setattr(settings, "trusted_proxy_ips", client.caller_address)


def account_key(clinic, email):
    return f"ratelimit:account:{clinic.id}:{email}"


async def wrong(client, clinic, email, source):
    return await client.post(
        "/auth/login",
        headers={"X-Tenant-Slug": clinic.slug, "X-Forwarded-For": source},
        json={"email": email, "password": "definitely-not-it"},
    )


async def right(client, clinic, source):
    return await client.post(
        "/auth/login",
        headers={"X-Tenant-Slug": clinic.slug, "X-Forwarded-For": source},
        json={"email": clinic.admin.email, "password": clinic.password},
    )


async def test_too_many_wrong_guesses_on_one_account_are_refused(
    client, clinic, redis, trust_the_test_client
):
    await redis.delete(account_key(clinic, clinic.admin.email))
    codes = [
        (await wrong(client, clinic, clinic.admin.email, f"9.9.9.{i}")).status_code
        for i in range(12)
    ]
    assert 429 in codes, f"the account guard never fired: {codes}"


async def test_a_correct_password_still_works_when_the_budget_is_full(
    client, clinic, redis, trust_the_test_client
):
    """The whole point. An attacker filling the budget must not lock the owner out."""
    await redis.delete(account_key(clinic, clinic.admin.email))

    # Bury the account under failures, each from a different machine.
    for i in range(settings.account_rate_limit + 2):
        await wrong(client, clinic, clinic.admin.email, f"9.9.9.{i}")

    # The real owner, from their own machine, with the right password.
    ok = await right(client, clinic, "5.5.5.5")
    assert ok.status_code == 200, "the owner was locked out by an attacker's failures"


async def test_a_success_clears_the_failure_count(
    client, clinic, redis, trust_the_test_client
):
    await redis.delete(account_key(clinic, clinic.admin.email))
    for i in range(3):
        await wrong(client, clinic, clinic.admin.email, f"9.9.9.{i}")
    assert await redis.zcard(account_key(clinic, clinic.admin.email)) == 3

    await right(client, clinic, "5.5.5.5")
    assert await redis.exists(account_key(clinic, clinic.admin.email)) == 0


async def test_a_successful_login_never_counts_against_the_budget(
    client, clinic, redis, trust_the_test_client
):
    await redis.delete(account_key(clinic, clinic.admin.email))
    for i in range(20):
        assert (await right(client, clinic, f"5.5.5.{i}")).status_code == 200
    # Twenty good logins, and the account is nowhere near locked.
    assert await redis.zcard(account_key(clinic, clinic.admin.email)) == 0


async def test_an_unknown_email_is_refused_the_same_way(
    client, clinic, redis, trust_the_test_client
):
    """No enumeration: a made-up email locks out just like a real one, so the
    lockout tells an attacker nothing about which emails exist."""
    ghost = f"nobody-{uuid.uuid4().hex[:8]}@example.com"
    await redis.delete(account_key(clinic, ghost))
    codes = [
        (await wrong(client, clinic, ghost, f"9.9.9.{i}")).status_code for i in range(12)
    ]
    assert 429 in codes


async def test_the_account_guard_can_be_exercised_directly(redis):
    """peek never records; record_failure does; clear resets."""
    limiter = RateLimiter(redis)
    key = f"ratelimit:test:{uuid.uuid4().hex}"

    for _ in range(5):
        assert (await limiter.peek(key, limit=3, window_seconds=60)).allowed
    # peek recorded nothing, so five peeks did not fill a budget of three.

    for _ in range(3):
        await limiter.record_failure(key, window_seconds=60)
    assert not (await limiter.peek(key, limit=3, window_seconds=60)).allowed

    await limiter.clear(key)
    assert (await limiter.peek(key, limit=3, window_seconds=60)).allowed
