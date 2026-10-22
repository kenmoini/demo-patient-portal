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


# --- signature / algorithm verification -------------------------------------

def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_bearer_rejects_token_signed_with_different_key(oidc_env, make_token, other_private_pem):
    # Same kid as the JWKS key, but signed by an attacker key -> signature must fail.
    forged = make_token(_key=other_private_pem)
    assert _client().get("/_api", headers=_bearer(forged)).status_code == 401


def test_bearer_rejects_unknown_kid(oidc_env, make_token):
    assert _client().get("/_api", headers=_bearer(make_token(_kid="no-such-kid"))).status_code == 401


def test_bearer_rejects_alg_none(oidc_env):
    import base64
    import json
    import time

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    now = int(time.time())
    claims = {"iss": TEST_ISSUER, "aud": "patient-portal", "sub": "x", "exp": now + 300}
    token = f"{b64({'alg': 'none', 'typ': 'JWT', 'kid': 'test-key-1'})}.{b64(claims)}."
    assert _client().get("/_api", headers=_bearer(token)).status_code == 401


def test_bearer_rejects_hs256_token(oidc_env):
    import time

    from jose import jwt as jose_jwt

    now = int(time.time())
    claims = {"iss": TEST_ISSUER, "aud": "patient-portal", "sub": "x", "exp": now + 300}
    token = jose_jwt.encode(claims, "attacker-secret", algorithm="HS256", headers={"kid": "test-key-1"})
    assert _client().get("/_api", headers=_bearer(token)).status_code == 401


def test_validate_token_tolerates_trailing_slash_issuer(oidc_env, make_token, monkeypatch):
    from app.auth import validate_token
    from app.config import get_settings

    monkeypatch.setenv("KEYCLOAK_ISSUER", TEST_ISSUER + "/")
    get_settings.cache_clear()
    assert validate_token(make_token())["sub"] == "user-123"


# --- require_session positive path ------------------------------------------

def test_require_session_accepts_session_claims(oidc_env):
    from fastapi import Request

    from app.auth import require_session
    from app.main import create_app

    app = create_app()

    @app.get("/_seed")
    def seed(request: Request):
        request.session["claims"] = {"sub": "user-123", "preferred_username": "dr.test"}
        return {"ok": True}

    @app.get("/_protected")
    def protected(claims: dict = Depends(require_session)):
        return claims

    c = TestClient(app, follow_redirects=False)
    c.get("/_seed")
    r = c.get("/_protected")
    assert r.status_code == 200
    assert r.json()["sub"] == "user-123"


# --- /auth/callback with a stubbed token endpoint ---------------------------

class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def _login_state(client):
    from urllib.parse import parse_qs, urlparse

    loc = client.get("/auth/login").headers["location"]
    return parse_qs(urlparse(loc).query)["state"][0]


def _stub_token_endpoint(monkeypatch, id_token, access_token="the-access-token"):
    from app import auth

    calls = []

    def fake_post(url, data=None, **kw):
        calls.append((url, data))
        return _FakeResp({"id_token": id_token, "access_token": access_token})

    monkeypatch.setattr(auth.httpx, "post", fake_post)
    return calls


def test_callback_happy_path_with_at_hash(oidc_env, make_token, monkeypatch):
    import hashlib

    from jose.utils import calculate_at_hash

    access = "the-access-token"
    id_token = make_token(at_hash=calculate_at_hash(access, hashlib.sha256))
    calls = _stub_token_endpoint(monkeypatch, id_token, access)
    c = _client()
    state = _login_state(c)

    r = c.get("/auth/callback", params={"code": "abc", "state": state})
    assert r.status_code == 303
    assert r.headers["location"] == "/"
    url, data = calls[0]
    assert url == f"{TEST_ISSUER}/protocol/openid-connect/token"
    assert data["code"] == "abc" and data["client_secret"] == "test-client-secret"
    # session now established
    assert c.get("/_protected").status_code == 200


def test_callback_rejects_bad_at_hash(oidc_env, make_token, monkeypatch):
    id_token = make_token(at_hash="AAAAAAAAAAAAAAAAAAAAAA")
    _stub_token_endpoint(monkeypatch, id_token)
    c = _client()
    state = _login_state(c)
    r = c.get("/auth/callback", params={"code": "abc", "state": state})
    assert r.status_code == 401
    assert c.get("/_protected").status_code == 307


def test_callback_rejects_state_mismatch(oidc_env, make_token, monkeypatch):
    calls = _stub_token_endpoint(monkeypatch, make_token())
    c = _client()
    _login_state(c)
    r = c.get("/auth/callback", params={"code": "abc", "state": "wrong"})
    assert r.status_code == 400
    assert calls == []  # no code exchange attempted
    assert c.get("/_protected").status_code == 307


# --- PKCE (S256) + IdP error responses --------------------------------------

def _pkce_from_location(location):
    from urllib.parse import parse_qs, urlparse

    q = parse_qs(urlparse(location).query)
    return q["state"][0], q["code_challenge"][0], q["code_challenge_method"][0]


def _s256(verifier: str) -> str:
    import base64
    import hashlib

    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()


def test_login_sends_pkce_s256_challenge(oidc_env):
    c = _client()
    _state, challenge, method = _pkce_from_location(c.get("/auth/login").headers["location"])
    assert method == "S256"
    assert len(challenge) == 43  # base64url(sha256) without padding
    assert "=" not in challenge and "+" not in challenge and "/" not in challenge


def test_require_session_redirect_sends_pkce_s256_challenge(oidc_env):
    _state, _challenge, method = _pkce_from_location(_client().get("/_protected").headers["location"])
    assert method == "S256"


def test_callback_sends_matching_code_verifier(oidc_env, make_token, monkeypatch):
    import hashlib

    from jose.utils import calculate_at_hash

    access = "the-access-token"
    id_token = make_token(at_hash=calculate_at_hash(access, hashlib.sha256))
    calls = _stub_token_endpoint(monkeypatch, id_token, access)
    c = _client()
    state, challenge, _method = _pkce_from_location(c.get("/auth/login").headers["location"])

    r = c.get("/auth/callback", params={"code": "abc", "state": state})
    assert r.status_code == 303
    _url, data = calls[0]
    assert 43 <= len(data["code_verifier"]) <= 128
    assert _s256(data["code_verifier"]) == challenge


def test_each_login_gets_a_fresh_verifier(oidc_env):
    c = _client()
    _s1, ch1, _m1 = _pkce_from_location(c.get("/auth/login").headers["location"])
    _s2, ch2, _m2 = _pkce_from_location(c.get("/auth/login").headers["location"])
    assert ch1 != ch2


def test_callback_reports_idp_error_instead_of_422(oidc_env, make_token, monkeypatch):
    calls = _stub_token_endpoint(monkeypatch, make_token())
    c = _client()
    state = _login_state(c)
    r = c.get(
        "/auth/callback",
        params={
            "error": "invalid_request",
            "error_description": "Missing parameter: code_challenge_method",
            "state": state,
        },
    )
    assert r.status_code == 401
    assert "invalid_request" in r.json()["detail"]
    assert "Missing parameter: code_challenge_method" in r.json()["detail"]
    assert calls == []  # no code exchange attempted
    assert c.get("/_protected").status_code == 307


def test_callback_without_code_or_error_is_400(oidc_env, make_token, monkeypatch):
    calls = _stub_token_endpoint(monkeypatch, make_token())
    c = _client()
    state = _login_state(c)
    r = c.get("/auth/callback", params={"state": state})
    assert r.status_code == 400
    assert calls == []
