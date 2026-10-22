from fastapi import Depends
from fastapi.testclient import TestClient

from tests.conftest import TEST_ISSUER


def _client():
    from app.auth import require_bearer, require_session
    from app.main import create_app

    app = create_app()

    @app.get("/_protected")
    def protected(claims: dict = Depends(require_session)):
        return claims

    @app.get("/_api")
    def api(claims: dict = Depends(require_bearer)):
        return claims

    return TestClient(app, follow_redirects=False)


def test_protected_route_redirects(oidc_env):
    r = _client().get("/_protected")
    assert r.status_code == 307
    assert r.headers["location"].startswith(f"{TEST_ISSUER}/protocol/openid-connect/auth?")
    assert "client_id=patient-portal" in r.headers["location"]


def test_bearer_accepts_valid_token(oidc_env, make_token):
    r = _client().get("/_api", headers={"Authorization": f"Bearer {make_token()}"})
    assert r.status_code == 200
    assert r.json()["sub"] == "user-123"
    assert r.json()["preferred_username"] == "dr.test"


def test_bearer_rejects_missing(oidc_env, make_token):
    c = _client()
    assert c.get("/_api").status_code == 401
    assert c.get("/_api", headers={"Authorization": "Bearer not-a-jwt"}).status_code == 401
    assert c.get("/_api", headers={"Authorization": "Basic abc"}).status_code == 401
    # valid signature but wrong audience / issuer / expired -> rejected
    assert c.get("/_api", headers={"Authorization": f"Bearer {make_token(aud='other')}"}).status_code == 401
    assert c.get("/_api", headers={"Authorization": f"Bearer {make_token(iss='https://evil/realms/x')}"}).status_code == 401
    assert c.get("/_api", headers={"Authorization": f"Bearer {make_token(exp=1)}"}).status_code == 401
