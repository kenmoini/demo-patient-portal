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

    def make(**overrides):
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
        return jose_jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": TEST_KID})

    return make
