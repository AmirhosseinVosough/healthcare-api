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
    # Rate limiting. Five attempts a minute is generous for a person typing a
    # password and useless to a script working through a dictionary.
    log_level: str = "INFO"
    rate_limit_enabled: bool = True
    auth_rate_limit: int = 5
    auth_rate_window_seconds: int = 60
    # A per-account limit that sits alongside the per-address one. It stops a
    # crowd of machines all attacking one account, which the address limit
    # cannot: the attacker chooses how many addresses they have. Only FAILED
    # logins count, so a person logging in normally is never affected by it.
    account_rate_limit: int = 10
    account_rate_window_seconds: int = 900  # 15 minutes

    # The addresses of proxies we trust to tell us who the real caller is.
    # Comma-separated, e.g. "127.0.0.1,10.0.0.1". EMPTY BY DEFAULT, which means
    # trust nobody: the caller is whoever actually opened the connection.
    #
    # X-Forwarded-For is a header, and a header is written by whoever sends the
    # request. Believed blindly, an attacker puts a new invented address in it
    # on every guess and gets a fresh allowance each time — the limiter becomes
    # decorative. We read it ONLY when the connection genuinely came from a
    # proxy in this list, because only then was the header written by our own
    # infrastructure rather than by the caller.
    #
    # Must be run with `uvicorn --no-proxy-headers`, so the framework does not
    # quietly do its own, looser version of this before our code is reached.
    trusted_proxy_ips: str = ""

    @property
    def trusted_proxies(self) -> set[str]:
        return {ip.strip() for ip in self.trusted_proxy_ips.split(",") if ip.strip()}

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
