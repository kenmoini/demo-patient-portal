"""Keycloak OIDC authentication: login/callback routes, token validation, auth dependencies."""

import secrets
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from jose import JWTError, jwt

from app.config import Settings, get_settings

router = APIRouter(prefix="/auth", tags=["auth"])

SESSION_CLAIMS_KEY = "claims"
SESSION_STATE_KEY = "oidc_state"


def fetch_jwks() -> dict:
    """Fetch the Keycloak JWKS. Module-level so tests can replace it with a stub."""
    resp = httpx.get(get_settings().jwks_url, timeout=10.0)
    resp.raise_for_status()
    return resp.json()


def _signing_key(token: str) -> dict:
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except JWTError as exc:
        raise JWTError("malformed token header") from exc
    for key in fetch_jwks().get("keys", []):
        if key.get("kid") == kid:
            return key
    raise JWTError("no matching signing key")


def validate_token(token: str, access_token: str | None = None) -> dict:
    """Validate an RS256 JWT against the Keycloak JWKS and return its claims.

    Pass `access_token` when validating an ID token so its `at_hash` claim is verified.
    """
    settings = get_settings()
    return jwt.decode(
        token,
        key=_signing_key(token),
        algorithms=["RS256"],
        audience=settings.KEYCLOAK_CLIENT_ID,
        issuer=settings.issuer,
        access_token=access_token,
    )


def _authorize_redirect(settings: Settings, state: str) -> str:
    query = urlencode(
        {
            "client_id": settings.KEYCLOAK_CLIENT_ID,
            "response_type": "code",
            "scope": "openid profile email",
            "redirect_uri": settings.redirect_uri,
            "state": state,
        }
    )
    return f"{settings.authorize_url}?{query}"


@router.get("/login")
def login(request: Request) -> RedirectResponse:
    """Redirect the browser to the Keycloak authorize endpoint."""
    state = secrets.token_urlsafe(24)
    request.session[SESSION_STATE_KEY] = state
    return RedirectResponse(_authorize_redirect(get_settings(), state), status_code=307)


@router.get("/callback")
def callback(request: Request, code: str, state: str | None = None) -> RedirectResponse:
    """Exchange the authorization code for tokens, validate, and start a session."""
    expected = request.session.pop(SESSION_STATE_KEY, None)
    if not expected or not state or not secrets.compare_digest(expected, state):
        raise HTTPException(status_code=400, detail="invalid state")
    settings = get_settings()
    try:
        resp = httpx.post(
            settings.token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.redirect_uri,
                "client_id": settings.KEYCLOAK_CLIENT_ID,
                "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
            },
            timeout=10.0,
        )
        resp.raise_for_status()
        tokens = resp.json()
        claims = validate_token(tokens["id_token"], access_token=tokens["access_token"])
    except (httpx.HTTPError, KeyError, ValueError, JWTError) as exc:
        raise HTTPException(status_code=401, detail="authentication failed") from exc
    request.session[SESSION_CLAIMS_KEY] = claims
    return RedirectResponse("/", status_code=303)


def require_session(request: Request) -> dict:
    """Dependency: claims from the signed-cookie session, else 307 to Keycloak."""
    claims = request.session.get(SESSION_CLAIMS_KEY)
    if claims:
        return claims
    state = secrets.token_urlsafe(24)
    request.session[SESSION_STATE_KEY] = state
    raise HTTPException(
        status_code=307,
        detail="authentication required",
        headers={"Location": _authorize_redirect(get_settings(), state)},
    )


def require_bearer(request: Request) -> dict:
    """Dependency: validate `Authorization: Bearer <jwt>` and return claims, else 401."""
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    try:
        return validate_token(token.strip())
    except (JWTError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=401, detail="invalid token", headers={"WWW-Authenticate": "Bearer"}) from exc
