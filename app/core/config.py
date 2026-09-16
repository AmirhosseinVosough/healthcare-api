from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# RFC 7518: an HMAC key for SHA-256 must be at least as long as the hash
# it feeds. A short secret is a guessable secret, and guessing it means
# minting a token for any clinic.
MIN_JWT_SECRET_BYTES = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env", env_file_encoding="utf-8", extra="ignore"
    )

    database_url: str
    redis_url: str
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    # bcrypt cost factor. 12 is the sane production default; tests drop it
    # to 4 so the suite is not spending a third of a second per login.
    bcrypt_rounds: int = 12
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    @field_validator("jwt_secret")
    @classmethod
    def _reject_weak_secret(cls, value: str) -> str:
        size = len(value.encode("utf-8"))
        if size < MIN_JWT_SECRET_BYTES:
            raise ValueError(
                f"JWT_SECRET is {size} bytes, needs at least {MIN_JWT_SECRET_BYTES}. "
                "Generate one with:  openssl rand -hex 32"
            )
        return value


settings = Settings()
