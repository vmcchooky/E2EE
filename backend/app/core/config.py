from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration sourced from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # Ignore extra fields from env
        env_ignore_empty=True,  # Ignore empty env values
    )

    environment: str = "development"
    algorithm: str = Field(default="HS256", env="ALGORITHM")
    api_v1_prefix: str = "/api"
    secret_key: str = "change-me"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    database_url: str = Field(default="mongodb://localhost:27017", env="DATABASE_URL")
    database_name: str = Field(default="e2ee_chat", env="DATABASE_NAME")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a memoized Settings instance."""
    return Settings()


