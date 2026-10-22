from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

# Synthetic demo fixture: this is a fake, non-functional AWS-style key.
RECORDS_EXPORT_KEY = "AKIAQ3X7LMPW5RTBN2HD"  # planted vuln #2 (see docs/EXPECTED_FINDINGS.md) — intentional, do not remove or suppress


class Settings(BaseSettings):
    """Runtime configuration. Every value here is read from the environment only."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str = "sqlite:///./patient_portal.sqlite3"
    KEYCLOAK_ISSUER: str = ""
    KEYCLOAK_CLIENT_ID: str = "patient-portal"
    KEYCLOAK_CLIENT_SECRET: str = ""
    KEYCLOAK_JWKS_URL: str = ""
    SESSION_SECRET: str = ""
    APP_BASE_URL: str = "http://localhost:8000"


@lru_cache
def get_settings() -> Settings:
    return Settings()
