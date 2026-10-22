# Patient Portal Fixture — Design Spec

Drafted 2026-10-22. Stack locked: Python FastAPI + HTMX. This is the fixture app
for the Agentic Purple-Teaming demo.

## Goal

A minimal, intentionally-vulnerable "patient portal" web app that serves as the
fixed target for the demo: the thing GitLab's scanners scan, the agent exploits
and fixes, and the dashboard replay seeds from. It is a fixture, not a product.

## Global constraints

- **Synthetic data only.** All patient records are fabricated; no real or
  realistic PHI anywhere.
- **Exactly three planted vulnerabilities, low-noise.** The app stays minimal
  enough that GitLab SAST, Secret Detection, and Dependency Scanning flag those
  three cleanly, with nothing incidental drowning them. None of the three
  carries a suppression comment.
- **Stack:** Python 3.12 + FastAPI; HTMX + Jinja2 for the UI; SQLAlchemy over
  Postgres (CNPG in-cluster, SQLite for local dev).
- **Auth:** the cluster's existing Keycloak via OIDC.
- **Topology:** authored in GitHub (source of truth), mirrored into in-cluster
  GitLab where CI and the agent's remediation MR run.
- **Baseline stability:** `main` stays vulnerable-as-specified; the fix lands via
  MR on a branch.

## Architecture

A single FastAPI service, server-rendered:

- **Backend** — one FastAPI app serving both HTMX pages (Jinja2) and a small
  JSON API. One service keeps the fixture easy to reason about and to sandbox.
- **Frontend** — HTMX + Jinja2, lightly themed for on-stage credibility. Flow:
  login → patient list → patient detail → patient search. No SPA or build step.
- **Database** — Postgres (CNPG) in-cluster, SQLite for local dev, via
  SQLAlchemy, seeded from a fixed-seed script.
- **Auth** — Keycloak OIDC auth-code flow guards the portal UI; token validation
  via python-jose. The vulnerable search API accepts a bearer token, so the
  agent exploits it with a client-credentials test token — no browser login in
  the exploit path.

Coherence note: the search box shown on stage *is* the vulnerable surface, so the
agent's exploit lands against the exact screen the audience just saw.

## Data model

`patients` table: `id` (PK), `mrn` (synthetic medical record number),
`full_name` (the searched field / SQLi target), `dob`, `sex` (FHIR-ish
demographics), `primary_condition` (display only), `attending_provider` (display
only), `created_at` (timestamp).

Around 100 fixed-seed Faker rows, plus one or two canary rows (e.g.
`mrn = ZZZ-CANARY-0001`) that make an exfiltration self-evident. No local
user/password store — identity comes from Keycloak claims. The patient detail
view mirrors a FHIR `Patient` resource shape without running a real FHIR server.

## Authentication / OIDC flow

- Confidential Keycloak client, authorization-code flow; redirect URI to the
  app; signed session cookie after callback.
- Token validated with python-jose (the CVE library — the theme closes on
  itself).
- The real Keycloak client secret is handled via env / External Secrets — it is
  **not** the planted secret.
- `/api/patients/search` accepts a bearer token (a client-credentials test token
  for the agent).

## The three planted vulnerabilities

| # | Type | Location | Caught by | Fix |
| --- | --- | --- | --- | --- |
| 1 (hero) | SQL injection | `app/routers/patients_api.py` — f-string query in `/api/patients/search` | GitLab SAST (Semgrep / Bandit B608) | Parameterize the query |
| 2 | Hardcoded secret | `app/config.py` — AWS-style "records export" key | GitLab Secret Detection (gitleaks) | Move to env / External Secrets |
| 3 | Vulnerable dependency | `requirements.txt` — python-jose ≤3.3.0 (CVE-2024-33663, JWT algorithm confusion) | GitLab Dependency Scanning (gemnasium) | Bump to the patched release |

**Hero (SQLi):** `... WHERE full_name LIKE '%{q}%'`, exploitable with
`%' OR '1'='1` or a `UNION SELECT` to dump patients / pull the canary. The agent
runs it in the sandbox, captures the canary row as evidence, and opens the
parameterizing MR. The secret and the CVE are real findings surfaced in the
dashboard (and remediable by the Ansible / MR paths) but are not the live
on-stage beat.

> Confirm the exact affected python-jose version trips GitLab's scanner at build
> time — that check is the acceptance for the dependency finding.

## Expected-findings manifest

`docs/EXPECTED_FINDINGS.md` is the oracle for every downstream task. One row per
planted finding: id, type, file:line, the scanner that must catch it, severity,
CVE/CWE, what "exploited" looks like, and the intended fix. Fresh subagents test
their work against it; the day-1 gate is "exactly these three light up, no more."

## Testing & acceptance

- **Vulnerability assertion (CI):** parse the scan reports and assert exactly the
  three expected findings appear — the day-1 "three clean findings" gate.
- **Smoke test:** app boots; login redirects to Keycloak; patient list and search
  render — the on-stage flow works.
- **Exploit reproduction:** the injection payload against `/api/patients/search`
  returns the canary row — proving the SQLi is live and giving the agent a
  known-good exploit to reproduce.

## Out of scope (YAGNI)

- A real FHIR server or full FHIR compliance — shape only.
- Local user management or RBAC beyond Keycloak claims.
- Any vulnerability beyond the three planted ones.
- Production concerns (scaling, HA) — it's a fixture.

## Open items to confirm during build

- The exact affected vs patched python-jose versions against GitLab's advisory DB.
- Whether the agent's remediation MR also round-trips to GitHub or stays in GitLab.
- Keycloak realm/client naming, to match the cluster's existing setup.

## Sources

- python-jose CVE-2024-33663 — Wiz vulnerability DB; Vicarius writeup.
- PyJWT CVE-2024-53861 — GitLab Advisory DB.
- python-multipart CVE-2024-24762 — GitLab Advisory DB.
