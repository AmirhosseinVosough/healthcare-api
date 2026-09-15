"""Password hashing.

Slow on purpose: the cost factor is what makes a stolen password table
expensive to crack offline rather than a weekend's work on a GPU.
"""

from passlib.context import CryptContext
from passlib.exc import UnknownHashError

from app.core.config import settings

# bcrypt only looks at the first 72 bytes of a password and silently ignores
# the rest, so "correct horse battery staple ...(200 more chars)" would be no
# stronger than its first 72. Reject those instead of pretending they worked.
MAX_PASSWORD_BYTES = 72

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.bcrypt_rounds,
)

# Built on first use, not at import, so app startup does not pay for a hash
# that most requests never need.
_dummy_hash: str | None = None
_DUMMY_PASSWORD = "not-a-real-password"


class PasswordTooLongError(ValueError):
    """Raised when a password would be silently truncated by bcrypt."""


def hash_password(password: str) -> str:
    """Return a salted bcrypt hash. Two calls on the same password differ."""
    size = len(password.encode("utf-8"))
    if size > MAX_PASSWORD_BYTES:
        raise PasswordTooLongError(
            f"password is {size} bytes; bcrypt accepts at most {MAX_PASSWORD_BYTES}"
        )
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Check a password against a stored hash. Never raises — returns False.

    A malformed or empty hash coming out of the database is a failed login,
    not a 500, so a corrupt row can't take the login endpoint down.
    """
    if len(plain_password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return False
    try:
        return pwd_context.verify(plain_password, password_hash)
    except (ValueError, TypeError, UnknownHashError):
        return False


def dummy_verify() -> None:
    """Burn the same time a real password check costs.

    Login calls this when the email doesn't exist. Without it, a missing
    account answers in microseconds and a real one takes ~370ms, and anyone
    can tell which emails are registered just by timing the 401s.
    """
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = pwd_context.hash(_DUMMY_PASSWORD)
    pwd_context.verify(_DUMMY_PASSWORD, _dummy_hash)
