from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


MAX_UNLOCK_TTL_SECONDS = 3_155_759_999


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCRYER_SECRETS_", extra="ignore")

    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8211)
    storage_root: Path = Field(default=Path("/var/lib/scryer-secrets"))
    service_name: str = Field(default="scryer-secrets")


settings = Settings()
