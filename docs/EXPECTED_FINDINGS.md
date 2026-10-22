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
>   to the GitLab report schema by `scripts/roxctl_to_gl_depscan.py`. ACS scans
>   the whole image, so the adapter keeps only the **declared** dependencies
>   (`requirements.txt`) and drops base-image OS CVEs. Because an image scan's
>   dependency surface is not controlled by this fixture, the verifier treats
>   dependency findings as **informational** — it asserts the planted
>   `CVE-2024-33663` is **present** but does not fail on extras (e.g. a second
>   CVE on `python-jose`, or any transitive). SAST and Secret, which come from
>   source files this fixture controls, stay strict (exactly the planted finding).
> - **Secret** → GitLab's managed Secret Detection, which is available on Free.
>
> Note: ACS may report more than one CVE on `python-jose` (it is the intentionally
> vulnerable package); all are the one planted "vulnerable dependency" finding and
> clear when the package is bumped. Any CVE on `python-jose` without an upstream fix
> will persist after the bump — relevant to the remediation/verify loop, not this gate.

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

## Matching rules used by the verifier

- SQLi (SAST, strict): a finding in `app/routers/patients_api.py` with CWE-89,
  Bandit `B608`, or the Semgrep rule id `sqlalchemy-text-fstring-sql-injection`.
- Secret (Secret Detection, strict): a finding in `app/config.py`.
- Dependency (informational): a finding carrying `CVE-2024-33663`.
- The gate FAILS if any of the three is missing, a report file is absent, or a
  SAST/Secret report carries any **other** High/Critical finding (those two are
  source-controlled). Dependency-report extras do **not** fail the gate — an ACS
  image scan reports the whole image (OS base layer, multiple CVEs per package),
  which this fixture does not control; they are printed as notes.

## Keeping it to the planted set

- The Semgrep SAST job scans only `app/`, so the vendored `app/static/htmx.min.js`
  and the `tests/`, `docs/`, `scripts/` trees add no SAST findings. Secret Detection
  excludes `tests/`, `docs/`, `scripts/` so no sample or doc copy becomes a fourth
  secret. Do not put the literal key anywhere except `app/config.py`.
- The ACS adapter scopes the dependency report to `requirements.txt` packages, so
  base-image OS CVEs don't appear in it. (`ACCEPTED_TRANSITIVE` / `--allow` in the
  verifier remain available for SAST/Secret allow-listing but are not needed for
  dependency findings, which are already informational.)
