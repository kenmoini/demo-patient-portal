import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base


def _fresh_session():
    """Return a session bound to a brand-new isolated in-memory SQLite DB."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


@pytest.fixture
def session():
    s = _fresh_session()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture
def session_factory():
    """Callable producing fresh, independent isolated sessions (for A/B runs)."""
    made = []

    def make():
        s = _fresh_session()
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


# ---------------------------------------------------------------------------
# OIDC test helpers: a throwaway RSA key + stubbed JWKS (no real Keycloak).
# ---------------------------------------------------------------------------
import time

import rsa
from jose import jwk as jose_jwk
from jose import jwt as jose_jwt

TEST_ISSUER = "https://keycloak.test/realms/portal"
TEST_CLIENT_ID = "patient-portal"
TEST_KID = "test-key-1"


@pytest.fixture(scope="session")
def oidc_keypair():
    """(private_pem, public_jwk_dict) for a throwaway RSA key."""
    _pub, priv = rsa.newkeys(2048)
    private_pem = priv.save_pkcs1().decode()
    public = jose_jwk.construct(private_pem, "RS256").public_key().to_dict()
    public.update({"kid": TEST_KID, "use": "sig", "alg": "RS256"})
    return private_pem, public


@pytest.fixture(scope="session")
def other_private_pem():
    """A DIFFERENT RSA private key (not in the JWKS), for forged-signature tests."""
    _pub, priv = rsa.newkeys(2048)
    return priv.save_pkcs1().decode()


@pytest.fixture
def oidc_env(monkeypatch, oidc_keypair):
    """Point Settings at a fake issuer and stub the JWKS source with the test key."""
    from app import auth
    from app.config import get_settings

    monkeypatch.setenv("KEYCLOAK_ISSUER", TEST_ISSUER)
    monkeypatch.setenv("KEYCLOAK_CLIENT_ID", TEST_CLIENT_ID)
    monkeypatch.setenv("KEYCLOAK_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("SESSION_SECRET", "test-session-secret")
    monkeypatch.setenv("APP_BASE_URL", "http://testserver")
    get_settings.cache_clear()
    _, public = oidc_keypair
    monkeypatch.setattr(auth, "fetch_jwks", lambda: {"keys": [public]})
    yield
    get_settings.cache_clear()


@pytest.fixture
def make_token(oidc_keypair):
    """Factory that signs a token with the test key; override claims as needed."""
    private_pem, _ = oidc_keypair

    def make(_key=None, _kid=TEST_KID, **overrides):
        now = int(time.time())
        claims = {
            "iss": TEST_ISSUER,
            "aud": TEST_CLIENT_ID,
            "sub": "user-123",
            "preferred_username": "dr.test",
            "iat": now,
            "exp": now + 300,
        }
        claims.update(overrides)
        return jose_jwt.encode(claims, _key or private_pem, algorithm="RS256", headers={"kid": _kid})

    return make


# ---------------------------------------------------------------------------
# Keep the app's own DB (used by startup) out of the repo cwd during tests.
# ---------------------------------------------------------------------------
def reset_db_engine():
    """Drop the cached engine so the next get_engine() re-reads Settings.DATABASE_URL."""
    from app import db

    db._engine = None
    db._SessionLocal = None


@pytest.fixture(autouse=True)
def isolated_database_url(tmp_path, monkeypatch):
    from app.config import get_settings

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.sqlite3'}")
    get_settings.cache_clear()
    reset_db_engine()
    yield
    reset_db_engine()
    get_settings.cache_clear()
