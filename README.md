# patient-portal (demo fixture)

> ⚠️ **Intentionally vulnerable.** This is a demo fixture for an Agentic AI
> Purple-Teaming demonstration. It contains **deliberately planted security
> vulnerabilities** and uses **synthetic data only** (no real PHI). Do not
> deploy it anywhere real.

A minimal FastAPI + HTMX "patient portal" used as the fixed target for the
purple-team demo: GitLab's scanners scan it, an AI agent exploits and fixes it,
and the dashboard replays the run.

- Design spec: `docs/superpowers/specs/2026-10-22-patient-portal-design.md`
- Implementation plan: `docs/superpowers/plans/2026-10-22-patient-portal.md`
- Planted findings manifest: `docs/EXPECTED_FINDINGS.md` (created in Task 6)

## Planted vulnerabilities (by design)

1. **SQL injection** (hero) — `GET /api/patients/search`
2. **Hardcoded secret** — AWS-style key in `app/config.py`
3. **Vulnerable dependency** — `python-jose` ≤3.3.0 (CVE-2024-33663)

## Stack

Python 3.12+, FastAPI, HTMX + Jinja2, SQLAlchemy (Postgres in-cluster / SQLite
for local dev), Keycloak OIDC.
