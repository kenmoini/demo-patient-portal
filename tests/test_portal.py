import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, Patient
from app.seed import seed


@pytest.fixture
def portal(oidc_env):
    """(anonymous_client, signed_in_client, first_patient, smith_names) on a seeded in-memory DB."""
    from app.db import get_session
    from app.main import create_app

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestSessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    with TestSessionLocal() as s:
        seed(s, n=100, seed=1337)
        first = s.scalars(select(Patient).order_by(Patient.id)).first()
        smiths = [p.full_name for p in s.scalars(select(Patient).where(Patient.full_name.like("%Smith%")))]

    def _override_get_session():
        s = TestSessionLocal()
        try:
            yield s
        finally:
            s.close()

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session

    @app.get("/_seed")
    def _seed_session(request: Request):
        request.session["claims"] = {"sub": "user-123", "preferred_username": "dr.test"}
        return {"ok": True}

    anon = TestClient(app, follow_redirects=False)
    authed = TestClient(app, follow_redirects=False)
    authed.get("/_seed")
    return anon, authed, first, smiths


def test_home_redirects_unauth(portal):
    anon, _, _, _ = portal
    r = anon.get("/")
    assert r.status_code == 307
    assert "/protocol/openid-connect/auth" in r.headers["location"]


def test_home_lists_patients(portal):
    _, authed, first, _ = portal
    r = authed.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert first.full_name in r.text
    assert 'hx-get="/search"' in r.text  # the demoed search box


def test_search_partial(portal):
    _, authed, _, smiths = portal
    assert smiths, "seed should contain Smith patients"
    r = authed.get("/search?q=Smith", headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "<html" not in r.text  # fragment, not a full page
    for name in smiths:
        assert name in r.text
    assert r.text.count("patient-row") == len(smiths)


def test_patient_detail(portal):
    _, authed, first, _ = portal
    r = authed.get(f"/patients/{first.id}")
    assert r.status_code == 200
    assert first.mrn in r.text
    assert first.full_name in r.text
    assert authed.get("/patients/999999").status_code == 404


def test_portal_routes_require_session(portal):
    anon, _, first, _ = portal
    for path in ("/search?q=Smith", f"/patients/{first.id}"):
        assert anon.get(path).status_code == 307


def test_portal_search_reuses_the_vulnerable_sink(portal):
    """The demoed search box IS the hero SQLi: the injection reaches the canary via the UI."""
    _, authed, _, _ = portal
    r = authed.get("/search", params={"q": "%' OR '1'='1"}, headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "ZZZ-CANARY-0001" in r.text


def test_portal_search_bad_sql_does_not_leak_error(portal):
    _, authed, _, _ = portal
    r = authed.get("/search", params={"q": "'"})
    assert r.status_code == 200
    assert "OperationalError" not in r.text and "SELECT" not in r.text


def test_static_assets_served(portal):
    anon, _, _, _ = portal
    assert anon.get("/static/app.css").status_code == 200
    assert anon.get("/static/htmx.min.js").status_code == 200
    assert anon.get("/signin").status_code == 200
