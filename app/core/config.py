from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


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


settings = Settings()
