"""Runtime configuration from OBS_* environment variables (contract section 6)."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The value .env.example ships with. Rejecting it makes `cp .env.example .env`
# (the footgun that silently reset credentials to a public placeholder) fail
# loudly at startup instead of serving a known password.
_PLACEHOLDER_SECRET = "CHANGE_ME_openssl_rand_hex_32"


class Settings(BaseSettings):
    """Every field maps 1:1 to an OBS_* environment variable from the contract.

    Required: OBS_SECRET_KEY, OBS_ADMIN_PASSWORD, OBS_INGEST_API_KEY.
    """

    model_config = SettingsConfigDict(
        case_sensitive=False,
        populate_by_name=True,
        extra="ignore",
    )

    secret_key: str = Field(validation_alias="OBS_SECRET_KEY")
    admin_user: str = Field(default="admin", validation_alias="OBS_ADMIN_USER")
    admin_password: str = Field(validation_alias="OBS_ADMIN_PASSWORD")
    ingest_api_key: str = Field(validation_alias="OBS_INGEST_API_KEY")

    @field_validator("secret_key", "admin_password", "ingest_api_key")
    @classmethod
    def _reject_placeholder(cls, value: str) -> str:
        if value == _PLACEHOLDER_SECRET:
            raise ValueError(
                "OBS_* secret is still the .env.example placeholder "
                "('CHANGE_ME_openssl_rand_hex_32') — set real values "
                "(bash install.sh, or openssl rand -hex 32 per docs/DEPLOYMENT.md §4)"
            )
        return value

    token_expire_minutes: int = Field(default=1440, validation_alias="OBS_TOKEN_EXPIRE_MINUTES")
    db_path: str = Field(default="/data/observatory.duckdb", validation_alias="OBS_DB_PATH")
    db_memory_limit: str = Field(default="128MB", validation_alias="OBS_DB_MEMORY_LIMIT")
    retention_days: int = Field(default=90, validation_alias="OBS_RETENTION_DAYS")
    queue_maxsize: int = Field(default=20000, validation_alias="OBS_QUEUE_MAXSIZE")
    sensor_ips: str = Field(default="", validation_alias="OBS_SENSOR_IPS")
    maxmind_license_key: str = Field(default="", validation_alias="OBS_MAXMIND_LICENSE_KEY")
    geoip_dir: str = Field(default="/data/geoip", validation_alias="OBS_GEOIP_DIR")
    geoip_enabled: bool = Field(default=True, validation_alias="OBS_GEOIP_ENABLED")
    log_level: str = Field(default="INFO", validation_alias="OBS_LOG_LEVEL")
    cors_origins: str = Field(default="http://localhost:5173", validation_alias="OBS_CORS_ORIGINS")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
