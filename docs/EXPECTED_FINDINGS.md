# Expected findings (the oracle)

This fixture is **intentionally vulnerable**. It contains exactly **three** planted
vulnerabilities. GitLab's scanners must surface these three and nothing else at
High/Critical; `scripts/verify_findings.py` (run by the `verify_findings` CI job
and by `tests/test_verify_findings.py`) enforces it. All data is synthetic; the
"key" below is a fake, non-functional string.

| # | id | Type | File:line | Scanner (GitLab) | Severity | CVE / CWE |
|---|----|------|-----------|------------------|----------|-----------|
| 1 | `sql-injection` | SQL injection (hero) | `app/routers/patients_api.py:58-60` (`run_vulnerable_search`, f-string `text(...)`; SAST usually anchors on the f-string, line 59) | SAST (Semgrep; Bandit B608 rule family) | High (analyzer-dependent: Bandit rates B608 Medium) | CWE-89 |
| 2 | `hardcoded-secret` | Hardcoded cloud credential (AWS-style access key) | `app/config.py:8` (`RECORDS_EXPORT_KEY`) | Secret Detection (gitleaks) | Critical | CWE-798 |
| 3 | `vulnerable-dependency` | Vulnerable dependency: JWT algorithm confusion in `python-jose==3.3.0` | `requirements.txt:5` | Dependency Scanning (gemnasium) | High | CVE-2024-33663 |

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

- SQLi: SAST finding in `app/routers/patients_api.py` with CWE-89 or Bandit `B608`.
- Secret: Secret Detection finding in `app/config.py`.
- Dependency: Dependency Scanning finding carrying `CVE-2024-33663`.
- Fails if any of the three is missing, a report file is absent, or any **other**
  High/Critical finding appears. Lower-severity extras are tolerated (noted), as are
  other advisories on `python-jose` itself (same root cause - e.g. CVE-2024-33664).

## Keeping the count at three

- `SAST_EXCLUDED_PATHS` (`.gitlab-ci.yml`) excludes `app/static/` (vendored
  `htmx.min.js`), `tests/`, `docs/` and `scripts/`; Secret Detection excludes the
  same test/doc paths so no sample or doc copy becomes a fourth finding. Do not put
  the literal key anywhere except `app/config.py`.
- If a scanner adds a legitimate transitive advisory (e.g. a High on a dependency of
  `python-jose`), triage it deliberately: pin/bump it, or pass
  `--allow <CVE-or-id>` to `verify_findings.py`.
