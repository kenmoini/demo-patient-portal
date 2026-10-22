import secrets
from functools import lru_cache

from pydantic import Field, field_validator
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
    OIDC_REDIRECT_URI: str = ""  # defaults to APP_BASE_URL + /auth/callback
    # Real value comes from env. If unset/empty, a random per-process key is generated
    # (fails safe: no known signing key in source; sessions just don't survive a restart).
    SESSION_SECRET: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    APP_BASE_URL: str = "http://localhost:8000"

    @field_validator("SESSION_SECRET", mode="after")
    @classmethod
    def _no_empty_session_secret(cls, v: str) -> str:
        return v or secrets.token_urlsafe(32)

    @property
    def issuer(self) -> str:
        return self.KEYCLOAK_ISSUER.rstrip("/")

    @property
    def authorize_url(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/auth"

    @property
    def token_url(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/token"

    @property
    def jwks_url(self) -> str:
        return self.KEYCLOAK_JWKS_URL or f"{self.issuer}/protocol/openid-connect/certs"

    @property
    def redirect_uri(self) -> str:
        return self.OIDC_REDIRECT_URI or f"{self.APP_BASE_URL.rstrip('/')}/auth/callback"


@lru_cache
def get_settings() -> Settings:
    return Settings()
