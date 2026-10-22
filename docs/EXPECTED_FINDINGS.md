# Expected findings (the oracle)

This fixture is **intentionally vulnerable**. It contains exactly **three** planted
vulnerabilities. GitLab's scanners must surface these three and nothing else at
High/Critical; `scripts/verify_findings.py` (run by the `verify_findings` CI job
and by `tests/test_verify_findings.py`) enforces it. All data is synthetic; the
"key" below is a fake, non-functional string.

| # | id | Type | File:line | Scanner (GitLab) | Severity | CVE / CWE |
|---|----|------|-----------|------------------|----------|-----------|
| 1 | `sql-injection` | SQL injection (hero) | `app/routers/patients_api.py:58` (`run_vulnerable_search`, `text(...)` built from an f-string) | Semgrep OSS, repo-local rule `ci/semgrep/sqli.yml` | High | CWE-89 |
| 2 | `hardcoded-secret` | Hardcoded cloud credential (AWS-style access key) | `app/config.py:8` (`RECORDS_EXPORT_KEY`) | Secret Detection (gitleaks, GitLab managed) | Critical | CWE-798 |
| 3 | `vulnerable-dependency` | Vulnerable dependency: JWT algorithm confusion in `python-jose==3.3.0` | `requirements.txt:5` (detected in the built image) | ACS / `roxctl image scan` → adapter | High | CVE-2024-33663 |

> **Scanner stack (GitLab Free).** GitLab Dependency Scanning, GitLab Advanced
> SAST, and SAST ruleset customization are Ultimate-only, so this fixture does
> not rely on them (see `.gitlab-ci.yml`):
> - **SQLi** → Semgrep OSS with `ci/semgrep/sqli.yml`. The rule is `text(...)`
>   minus a static-string argument: it matches the concatenated-f-string sink
>   and stops matching once the query is parameterized (the fix). Semgrep OSS
>   does not emit a CWE identifier into its `--gitlab-sast` output, so the
>   verifier matches this finding by the rule id `sqlalchemy-text-fstring-sql-injection`.
> - **Dependency** → ACS (`roxctl image scan`) against the built image, adapted
>   to the GitLab report schema by `scripts/roxctl_to_gl_depscan.py`. Because ACS
>   scans the whole image, the adapter keeps **only language-level findings** and
>   drops base-image OS CVEs, so they don't appear as unexpected findings.
> - **Secret** → GitLab's managed Secret Detection, which is available on Free.

## What "exploited" looks like

1. **sql-injection** - `GET /api/patients/search?q=` (and the portal's `/search`
   partial) interpolates `q` straight into SQL. A payload such as a `UNION SELECT`
   in `q` returns rows that are not patient matches (e.g. the seeded canary record /
   other tables' data), or a tautology like `' OR '1'='1` returns every patient
   regardless of the search term.
2. **hardcoded-secret** - the credential is readable by anyone with repo access:
   it is recovered verbatim from `app/config.py` (or git history) and presented
   as a working export credential. Exploitation = extracting the value from source
   without ever touching the running app.
3. **vulnerable-dependency** - an attacker forges a JWT using the algorithm-confusion
   weakness (an OpenSSH-format ECDSA public key accepted as an HMAC secret), and the
   app accepts the forged token as authentic, granting access without valid Keycloak
   credentials.

## Intended fix

1. **sql-injection** - parameterize: `text("... WHERE full_name LIKE :pattern")`
   with `session.execute(query, {"pattern": f"%{q}%"})`.
2. **hardcoded-secret** - remove the literal; read it from the environment
   (`Settings` / env var) populated in-cluster via External Secrets, and rotate the
   exposed value.
3. **vulnerable-dependency** - bump `python-jose` to the patched release
   (`>=3.4.0`) in `requirements.txt`.

## Known, accepted extras (documented, not silent)

| id | Package | Severity | Why accepted |
|----|---------|----------|--------------|
| `CVE-2024-23342` | `ecdsa` (transitive dependency of `python-jose`) | High | Minerva timing side-channel; no upstream fix exists. Cannot be removed without changing the pinned `python-jose==3.3.0`, which is part of the planted finding. |

These are listed in `ACCEPTED_TRANSITIVE` in `scripts/verify_findings.py`, so the
gate passes out of the box on the first real pipeline run. The list is explicit:
every other High/Critical (including any new advisory on `python-jose` or `ecdsa`)
still fails the gate as unexpected.

## Matching rules used by the verifier

- SQLi: SAST finding in `app/routers/patients_api.py` with CWE-89, Bandit `B608`, or the Semgrep rule id `sqlalchemy-text-fstring-sql-injection`.
- Secret: Secret Detection finding in `app/config.py`.
- Dependency: Dependency Scanning finding carrying `CVE-2024-33663`.
- Fails if any of the three is missing, a report file is absent, or any **other**
  High/Critical finding appears (other than the accepted list above). There is no
  blanket waiver for `python-jose`. Lower-severity extras are tolerated (noted).

## Keeping the count at three

- The Semgrep SAST job scans only `app/`, so the vendored `app/static/htmx.min.js`
  and the `tests/`, `docs/`, `scripts/` trees add no SAST findings. Secret Detection
  excludes `tests/`, `docs/`, `scripts/` so no sample or doc copy becomes a fourth
  secret. The ACS adapter drops base-image OS CVEs (language-level findings only).
  Do not put the literal key anywhere except `app/config.py`.
- If a scanner reports another legitimate transitive advisory, triage it
  deliberately: pin/bump it, or add it to `ACCEPTED_TRANSITIVE` (with rationale and
  a row in the table above), or pass `--allow <CVE-or-id>` for a one-off.
