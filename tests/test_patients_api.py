from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import pytest

from app.models import Base
from app.seed import seed


@pytest.fixture
def client(oidc_env):
    """TestClient wired to a fresh, seeded in-memory SQLite DB (includes the canary)."""
    from app.db import get_session
    from app.main import create_app

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestSessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    session = TestSessionLocal()
    try:
        seed(session, n=100, seed=1337)
    finally:
        session.close()

    def _override_get_session():
        s = TestSessionLocal()
        try:
            yield s
        finally:
            s.close()

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session

    with TestClient(app) as c:
        yield c


@pytest.fixture
def token(make_token):
    return make_token()


def test_search_normal(client, token):
    r = client.get("/api/patients/search?q=Smith", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert all("Smith" in p["full_name"] for p in r.json())


def test_sqli_returns_canary(client, token):
    # the injection is the acceptance: it MUST succeed
    payload = "%' OR '1'='1"
    r = client.get(f"/api/patients/search?q={payload}", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert any(p["mrn"] == "ZZZ-CANARY-0001" for p in r.json())


def test_requires_bearer(client):
    assert client.get("/api/patients/search?q=x").status_code == 401
