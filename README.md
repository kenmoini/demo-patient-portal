# patient-portal (demo fixture)

> ⚠️ **Intentionally vulnerable.** This is a demo fixture for an Agentic AI
> Purple-Teaming demonstration. It contains **deliberately planted security
> vulnerabilities** and uses **synthetic data only** (no real PHI). Do not
> deploy it anywhere real.

A minimal FastAPI + HTMX "patient portal" used as the fixed target for the
purple-team demo: security scanners scan it, an AI agent exploits and fixes it,
and a dashboard replays the run. It ships with a Keycloak-OIDC-guarded UI
(landing page, login with PKCE, logout), a patient list / detail / live search,
a JSON API, container build, and Kubernetes/OpenShift deploy manifests.

## Planted vulnerabilities (by design)

1. **SQL injection** (hero) — the shared search sink in `app/routers/patients_api.py`, reached by both `GET /api/patients/search` and the portal search box.
2. **Hardcoded secret** — an AWS-style key in `app/config.py`.
3. **Vulnerable dependency** — `python-jose==3.3.0` (CVE-2024-33663).

All three, plus the known transitive `ecdsa` advisory (CVE-2024-23342), are
documented in `docs/EXPECTED_FINDINGS.md`, which the CI verify gate uses as its
oracle.

## Stack

Python 3.12+, FastAPI, HTMX + Jinja2, SQLAlchemy (SQLite for local dev / a
mounted volume in-cluster), Keycloak OIDC (authorization-code + PKCE),
containerized and deployed via Kustomize.

## Run locally

```bash
pip install -r requirements.txt
cp .env.example .env  # see it for the env vars app.config.Settings reads
# set env (DATABASE_URL defaults to SQLite; Keycloak + SESSION_SECRET for auth), then:
uvicorn app.main:app --reload
```

Seed synthetic patients (incl. the canary row) via `app/seed.py`. Run the tests
with `python -m pytest`.

## Container image

Built and pushed as a multi-arch image to `ghcr.io/kenmoini/demo-patient-portal`
by `.github/workflows/build-container.yaml` (GitHub Actions). Build locally from
the `Containerfile`.

## Deploy (Kubernetes / OpenShift)

Kustomize manifests live under `deploy/`:

- `deploy/base` — Deployment (non-root, dropped caps), Service, ServiceAccount, Namespace, PVC, and an **example** config Secret.
- `deploy/overlays/openshift` — adds a Route, a root-CA ConfigMap, and env/volume patches.

Copy `deploy/base/example.oidc-secret.yaml`, fill in the real values (the
`REPLACE_ME` placeholders — generate `SESSION_SECRET` with `openssl rand -hex 32`),
and apply with `kubectl apply -k deploy/base` (or `deploy/overlays/openshift`).
Never commit real secret values.

## CI & security scanning

- **GitLab** (`.gitlab-ci.yml`) runs SAST, Secret Detection, and Dependency
  Scanning, then `scripts/verify_findings.py` asserts **exactly** the three
  planted findings appear — failing on a missing finding or an unexpected
  High/Critical (the transitive `ecdsa` CVE is explicitly allowlisted). Vendored
  static and test/doc paths are excluded from the scanners so they add no noise.
- **GitHub Actions** builds and publishes the container image.
