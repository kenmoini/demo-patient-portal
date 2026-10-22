# Patient Portal Fixture — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the intentionally-vulnerable FastAPI + HTMX patient-portal fixture with exactly three planted, scanner-detectable vulnerabilities and a believable Keycloak-OIDC-guarded UI.

**Architecture:** A single FastAPI service, server-rendered with HTMX + Jinja2, SQLAlchemy over Postgres (SQLite for dev), Keycloak OIDC. The patient-search API carries the hero SQL injection.

**Tech Stack:** Python 3.12, FastAPI, HTMX, Jinja2, SQLAlchemy, python-jose (pinned ≤3.3.0 — CVE-2024-33663), Faker, pytest + httpx.

**Spec:** `docs/superpowers/specs/2026-10-22-patient-portal-design.md`

## Global Constraints

- Python 3.12; all dependencies pinned in `requirements.txt`; `python-jose` pinned to an affected version (≤3.3.0).
- Synthetic data only; no real PHI.
- Exactly three planted vulns (SQLi, hardcoded secret, vulnerable dependency); nothing incidental may trip the scanners, and none of the three carries a suppression comment.
- `main` stays vulnerable-as-specified; fixes land via MR on a branch.
- Authored in GitHub; mirrored to in-cluster GitLab for CI and the agent's MR.
- Commits end with the standard `Co-Authored-By: Claude Opus 4.8` trailer and the session link.
- Tests run under pytest; install deps with `pip install --break-system-packages -r requirements.txt` (or a venv). Test output must be pristine.

## Review Focus

- **The three vulns must stay present and detectable** — a refactor or linter autofix must not silently remove the SQLi or the secret before the demo. Pinned by Task 4's injection test and Task 6's verify script.
- **The injection must return the canary row deterministically**, independent of seed order. Pinned by Task 2 determinism + Task 4.
- **OIDC must not block the exploit path** — the search API must accept a client-credentials bearer token, not only a browser session. Pinned by Task 3's bearer test.
- **No incidental findings beyond the three** — debug mode off, no second hardcoded value, no extra weak dependency. Pinned by Task 6's "exactly three" assertion.
- **The SQLi behaves on both SQLite (dev) and Postgres (cluster)** — run the exploit-reproduction test against both where practical.

---

### Task 1: Project scaffold & config

**Files:**
- Create: `app/__init__.py`, `app/main.py`, `app/config.py`, `requirements.txt`, `Containerfile`, `.env.example`
- Test: `tests/test_app_boots.py`

**Interfaces:**
- Produces: `create_app() -> FastAPI` (with `GET /healthz -> {"status": "ok"}`); `Settings` (pydantic settings read from env). Also introduces the deliberately hardcoded `RECORDS_EXPORT_KEY` constant in `config.py` (planted vuln #2, AWS-style key, no suppression comment). Real secrets (Keycloak client secret, DB URL) come from env only.

- [ ] **Step 1: Write the failing test** in `tests/test_app_boots.py`:

```python
def test_healthz():
    from app.main import create_app
    from fastapi.testclient import TestClient
    r = TestClient(create_app()).get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
```

- [ ] **Step 2:** Run `pytest tests/test_app_boots.py -v` — expect FAIL (`create_app` undefined)
- [ ] **Step 3:** Implement `create_app()` in `app/main.py` and `Settings` in `app/config.py`; pin deps in `requirements.txt` (fastapi, uvicorn[standard], jinja2, sqlalchemy, python-jose==3.3.0, python-multipart, pydantic-settings, faker, httpx, pytest); add the planted `RECORDS_EXPORT_KEY` constant in `config.py` with an inline comment referencing `EXPECTED_FINDINGS` #2 (no suppression); write a minimal `Containerfile` and `.env.example`
- [ ] **Step 4:** Run `pytest tests/test_app_boots.py -v` — expect PASS
- [ ] **Step 5:** Commit

### Task 2: Data model, DB & deterministic seed

**Files:**
- Create: `app/db.py`, `app/models.py`, `app/seed.py`
- Test: `tests/test_seed.py`

**Interfaces:**
- Consumes: `Settings` (Task 1).
- Produces: the `Patient` model (`id`, `mrn`, `full_name`, `dob`, `sex`, `primary_condition`, `attending_provider`, `created_at`); `get_session()`; `seed(session, n=100, seed=1337)` which inserts deterministic Faker rows plus a canary (`mrn="ZZZ-CANARY-0001"`, `full_name="Canary Testpatient"`).

- [ ] **Step 1: Write failing tests** in `tests/test_seed.py`: `test_seed_is_deterministic` (same seed → identical first `full_name` across two runs) and `test_canary_present` (query `mrn == "ZZZ-CANARY-0001"` returns exactly one row)
- [ ] **Step 2:** Run — expect FAIL
- [ ] **Step 3:** Implement `models.py`, `db.py` (engine from `Settings.DATABASE_URL`, SQLite default for dev), and `seed.py` with a fixed Faker seed
- [ ] **Step 4:** Run — expect PASS
- [ ] **Step 5:** Commit

### Task 3: OIDC authentication (python-jose)

**Files:**
- Create: `app/auth.py`
- Modify: `app/main.py` (mount login/callback)
- Test: `tests/test_auth.py`

**Interfaces:**
- Consumes: `Settings` (issuer, client id/secret, JWKS URL).
- Produces: `login()` (redirect to Keycloak authorize URL), `callback(code)` (code exchange + `validate_token`), `validate_token(token) -> claims` (python-jose `jwt.decode` against Keycloak JWKS), a `require_session` dependency (signed cookie → claims, else redirect), and a `require_bearer` dependency (validates `Authorization: Bearer` → claims, else 401).

- [ ] **Step 1: Write failing tests** in `tests/test_auth.py`: `test_protected_route_redirects` (no session → 307 to Keycloak), `test_bearer_accepts_valid_token` (test-signed token → claims), `test_bearer_rejects_missing` (no/invalid token → 401). Use a test RSA key + stubbed JWKS for unit tests.
- [ ] **Step 2:** Run — expect FAIL
- [ ] **Step 3:** Implement `auth.py` with python-jose `jwt.decode`, a signed session cookie, and the two dependencies. Keep the real client secret in env; keep `python-jose` pinned (do **not** bump it — the CVE is intentional).
- [ ] **Step 4:** Run — expect PASS
- [ ] **Step 5:** Commit

### Task 4: Patients API + the SQL injection (hero)

**Files:**
- Create: `app/routers/__init__.py`, `app/routers/patients_api.py`
- Modify: `app/main.py` (include router)
- Test: `tests/test_patients_api.py`

**Interfaces:**
- Consumes: `Patient`/`get_session` (Task 2) and `require_bearer` (Task 3).
- Produces: `GET /api/patients` (safe, parameterized, paginated) and `GET /api/patients/search?q=` (the VULNERABLE endpoint — builds SQL by f-string: `... WHERE full_name LIKE '%{q}%'`), both behind `require_bearer`.

- [ ] **Step 1: Write failing tests** in `tests/test_patients_api.py`:

```python
def test_search_normal(client, token):
    r = client.get("/api/patients/search?q=Smith", headers={"Authorization": f"Bearer {token}"})
    assert all("Smith" in p["full_name"] for p in r.json())

def test_sqli_returns_canary(client, token):
    # the injection is the acceptance: it MUST succeed
    payload = "%' OR '1'='1"
    r = client.get(f"/api/patients/search?q={payload}", headers={"Authorization": f"Bearer {token}"})
    assert any(p["mrn"] == "ZZZ-CANARY-0001" for p in r.json())

def test_requires_bearer(client):
    assert client.get("/api/patients/search?q=x").status_code == 401
```

- [ ] **Step 2:** Run — expect FAIL
- [ ] **Step 3:** Implement the router. The search uses the deliberate f-string query with an inline comment referencing `EXPECTED_FINDINGS` #1 (no suppression); the list endpoint uses a parameterized query
- [ ] **Step 4:** Run — expect PASS (normal search and the injection both behave as written)
- [ ] **Step 5:** Commit

### Task 5: HTMX portal UI

**Files:**
- Create: `app/routers/portal.py`, `app/templates/base.html`, `app/templates/login.html`, `app/templates/patients_list.html`, `app/templates/patient_detail.html`, `app/templates/_search_results.html`, `app/static/app.css`
- Modify: `app/main.py`
- Test: `tests/test_portal.py`

**Interfaces:**
- Consumes: `require_session` (Task 3), `Patient`/`get_session` (Task 2), and the search API (Task 4).
- Produces: `GET /` (patient list), `GET /patients/{id}` (detail, FHIR-ish layout), and `GET /search` (HTMX partial). Light theme in `app.css`.

- [ ] **Step 1: Write failing tests** in `tests/test_portal.py`: `test_home_redirects_unauth` (→ Keycloak), `test_home_lists_patients` (with session → HTML contains a known seeded name), `test_search_partial` (HTMX `GET /search?q=Smith` → table fragment with matching rows)
- [ ] **Step 2:** Run — expect FAIL
- [ ] **Step 3:** Implement routes, Jinja2 templates with HTMX attributes, and minimal CSS
- [ ] **Step 4:** Run — expect PASS
- [ ] **Step 5:** Commit

### Task 6: GitLab CI scanners + expected-findings manifest

**Files:**
- Create: `.gitlab-ci.yml`, `docs/EXPECTED_FINDINGS.md`, `scripts/verify_findings.py`
- Test: `tests/test_verify_findings.py`

**Interfaces:**
- Produces: the CI pipeline (SAST + Secret Detection + Dependency Scanning template includes) and `verify_findings(report_dir) -> None` which asserts exactly the three expected findings are present (by rule / CVE / path) and no other Critical finding surprises.

- [ ] **Step 1:** Write `docs/EXPECTED_FINDINGS.md`: a table of the three findings — id, type, file:line, scanner, severity, CVE/CWE, what "exploited" looks like, intended fix
- [ ] **Step 2: Write the failing test** `tests/test_verify_findings.py`: runs `verify_findings` against committed sample report fixtures — asserts the three are present and no unexpected Critical — expect FAIL (script missing)
- [ ] **Step 3:** Implement `scripts/verify_findings.py` (parse the GitLab `gl-*-report.json` artifacts) and `.gitlab-ci.yml` (scanner template includes + a job that runs `verify_findings.py` after them)
- [ ] **Step 4:** Run the test — expect PASS; then (in GitLab) run the pipeline — exactly the three findings appear in the MR security widget (the day-1 acceptance gate)
- [ ] **Step 5:** Commit
