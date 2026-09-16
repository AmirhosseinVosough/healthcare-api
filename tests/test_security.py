"""Phase 2 — password hashing. No database, no HTTP."""

import time

import pytest

from app.core.security import (
    MAX_PASSWORD_BYTES,
    PasswordTooLongError,
    dummy_verify,
    hash_password,
    verify_password,
)

PASSWORD = "correct horse battery staple"


def test_hash_does_not_contain_the_password():
    assert PASSWORD not in hash_password(PASSWORD)


def test_hash_looks_like_bcrypt():
    assert hash_password(PASSWORD).startswith("$2b$")


def test_same_password_hashes_differently():
    """Each hash carries its own salt, so equal passwords are not equal rows."""
    assert hash_password(PASSWORD) != hash_password(PASSWORD)


def test_correct_password_verifies():
    assert verify_password(PASSWORD, hash_password(PASSWORD)) is True


def test_wrong_password_is_rejected():
    assert verify_password("wrong password", hash_password(PASSWORD)) is False


@pytest.mark.parametrize("password", ["", "pässwörd-✓", "a" * MAX_PASSWORD_BYTES])
def test_edge_case_passwords_round_trip(password):
    assert verify_password(password, hash_password(password)) is True


def test_password_one_byte_too_long_is_refused():
    """bcrypt ignores everything past 72 bytes; refuse rather than truncate."""
    with pytest.raises(PasswordTooLongError):
        hash_password("a" * (MAX_PASSWORD_BYTES + 1))


def test_length_limit_counts_bytes_not_characters():
    """24 emoji are 24 characters but 96 bytes, so this must still be refused."""
    password = "🔒" * 24
    assert len(password) < MAX_PASSWORD_BYTES < len(password.encode("utf-8"))
    with pytest.raises(PasswordTooLongError):
        hash_password(password)


def test_verify_refuses_overlong_password_without_raising():
    assert verify_password("a" * 200, hash_password(PASSWORD)) is False


@pytest.mark.parametrize("bad_hash", ["", "not-a-hash", "$2b$12$tooshort", None])
def test_malformed_stored_hash_fails_login_instead_of_crashing(bad_hash):
    """A corrupt row is a failed login, not a 500 that takes the endpoint down."""
    assert verify_password(PASSWORD, bad_hash) is False


def test_unknown_user_check_costs_the_same_as_a_real_one():
    """Login calls dummy_verify() when the email is unknown.

    Without it a missing account answers in microseconds and a real one takes a
    full bcrypt round, so anyone could map which emails are registered just by
    timing the 401s. Best-of-5 on each side to shake out scheduler noise.
    """
    stored = hash_password(PASSWORD)
    dummy_verify()  # first call builds and caches its hash; don't time that one

    def best_of_5(fn):
        return min(_timed(fn) for _ in range(5))

    real = best_of_5(lambda: verify_password(PASSWORD, stored))
    unknown = best_of_5(dummy_verify)
    assert max(real, unknown) / min(real, unknown) < 3.0


def _timed(fn):
    start = time.perf_counter()
    fn()
    return time.perf_counter() - start
