#!/usr/bin/env python3
"""Verify that GitLab's scanners found EXACTLY the three planted vulnerabilities.

Reads the GitLab security report JSON artifacts from a directory:

    gl-sast-report.json
    gl-secret-detection-report.json
    gl-dependency-scanning-report.json

and asserts (see docs/EXPECTED_FINDINGS.md):

  1. sql-injection        SAST, CWE-89 / Bandit B608, in app/routers/patients_api.py
  2. hardcoded-secret     Secret Detection, in app/config.py
  3. vulnerable-dependency Dependency Scanning, CVE-2024-33663 (python-jose)

It FAILS (FindingsMismatch / exit code 1) when an expected finding is missing,
a report file is absent or unreadable, or an UNEXPECTED High/Critical finding
appears. Lower-severity extras are reported as notes but tolerated (use
--strict to fail on those too).

There is NO blanket waiver for python-jose: any advisory on it (or its
dependency closure) other than the expected CVE-2024-33663 and the explicit
ACCEPTED_TRANSITIVE list below is "unexpected" and fails if High/Critical.

Plain stdlib only (json, pathlib, argparse).
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

SAST_REPORT = "gl-sast-report.json"
SECRET_REPORT = "gl-secret-detection-report.json"
DEPENDENCY_REPORT = "gl-dependency-scanning-report.json"
REPORT_FILES = (SAST_REPORT, SECRET_REPORT, DEPENDENCY_REPORT)

BLOCKING_SEVERITIES = {"high", "critical"}

SQLI_FILE = "app/routers/patients_api.py"
SECRET_FILE = "app/config.py"
DEPENDENCY_FILE = "requirements.txt"
DEPENDENCY_CVE = "CVE-2024-33663"
DEPENDENCY_PACKAGE = "python-jose"


# Known, ACCEPTED extras (documented in docs/EXPECTED_FINDINGS.md): transitive
# advisories that the pinned python-jose==3.3.0 drags in and that cannot be
# separately fixed. Keyed by identifier (CVE); value is the rationale.
# Keep this list explicit and minimal - anything else High/Critical must fail.
ACCEPTED_TRANSITIVE = {
    "CVE-2024-23342": "ecdsa (transitive via python-jose), High, no upstream fix (Minerva timing attack)",
}


class FindingsMismatch(AssertionError):
    """The scanner output does not match the expected-findings manifest."""


Finding = dict


def _norm_path(path: str | None) -> str:
    p = (path or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def _file_of(finding: Finding) -> str:
    return _norm_path((finding.get("location") or {}).get("file"))


def _identifier_values(finding: Finding) -> set[str]:
    """All identifier values/names, upper-cased (e.g. '89', 'CWE-89', 'B608')."""
    out: set[str] = set()
    for ident in finding.get("identifiers") or []:
        for key in ("value", "name"):
            v = ident.get(key)
            if v:
                out.add(str(v).upper())
    return out


def _has_cwe(finding: Finding, number: str) -> bool:
    for ident in finding.get("identifiers") or []:
        if str(ident.get("type", "")).lower() == "cwe":
            val = str(ident.get("value", "")).upper().replace("CWE-", "")
            if val == number:
                return True
    return False


def _package_of(finding: Finding) -> str:
    dep = (finding.get("location") or {}).get("dependency") or {}
    return str((dep.get("package") or {}).get("name", "")).lower()


@dataclass(frozen=True)
class Expected:
    id: str
    report: str
    description: str
    matches: Callable[[Finding], bool]


# Our Semgrep OSS rule id (ci/semgrep/sqli.yml). Semgrep OSS does not emit a CWE
# identifier into --gitlab-sast output, so we also match the SQLi by this rule id.
SQLI_RULE_ID = "SQLALCHEMY-TEXT-FSTRING-SQL-INJECTION"


def _is_sqli(f: Finding) -> bool:
    # SQLi in the planted file, identified by CWE-89, Bandit B608, or our
    # Semgrep rule id (identifier values are upper-cased; the rule id may be
    # namespaced, e.g. "ci.semgrep.sqli.sqlalchemy-text-fstring-sql-injection").
    if _file_of(f) != SQLI_FILE:
        return False
    idents = _identifier_values(f)
    return (
        _has_cwe(f, "89")
        or "B608" in idents
        or any(SQLI_RULE_ID in v for v in idents)
    )


def _is_secret(f: Finding) -> bool:
    # any Secret Detection finding located in the planted file
    return _file_of(f) == SECRET_FILE


def _is_vulnerable_dependency(f: Finding) -> bool:
    return DEPENDENCY_CVE in _identifier_values(f)


EXPECTED = (
    Expected("sql-injection", SAST_REPORT,
             f"SAST SQL injection (CWE-89 / B608) in {SQLI_FILE}", _is_sqli),
    Expected("hardcoded-secret", SECRET_REPORT,
             f"Secret Detection finding in {SECRET_FILE}", _is_secret),
    Expected("vulnerable-dependency", DEPENDENCY_REPORT,
             f"Dependency Scanning {DEPENDENCY_CVE} ({DEPENDENCY_PACKAGE})", _is_vulnerable_dependency),
)


def _load(report_dir: Path, name: str, problems: list[str]) -> list[Finding]:
    path = report_dir / name
    if not path.is_file():
        problems.append(f"report file missing: {name} (looked in {report_dir})")
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        vulns = data["vulnerabilities"]
        if not isinstance(vulns, list):
            raise TypeError("'vulnerabilities' is not a list")
    except (ValueError, KeyError, TypeError) as exc:
        problems.append(f"report file unreadable: {name} ({exc})")
        return []
    return vulns


def _describe(f: Finding) -> str:
    loc = f.get("location") or {}
    where = loc.get("file", "?")
    if loc.get("start_line"):
        where += f":{loc['start_line']}"
    ids = ", ".join(sorted(_identifier_values(f))) or "no identifiers"
    return f"[{f.get('severity', '?')}] {f.get('name', f.get('id', '?'))} @ {where} ({ids})"


def verify_findings(
    report_dir,
    *,
    strict: bool = False,
    allow: tuple[str, ...] = (),
    accepted_transitive=ACCEPTED_TRANSITIVE,
) -> None:
    """Assert the reports in `report_dir` contain exactly the three planted findings.

    Returns None on success; raises FindingsMismatch listing every problem otherwise.
    `accepted_transitive` (default ACCEPTED_TRANSITIVE) is the documented set of
    known transitive CVEs that are ignored; pass () to disable it. `allow` adds
    further finding ids / identifier values to ignore. With `strict`, any other
    extra finding fails, not just High/Critical.
    """
    report_dir = Path(report_dir)
    problems: list[str] = []
    allowed = {a.upper() for a in (*accepted_transitive, *allow)}

    reports = {name: _load(report_dir, name, problems) for name in REPORT_FILES}

    claimed: set[int] = set()
    for exp in EXPECTED:
        hits = [f for f in reports[exp.report] if exp.matches(f)]
        if not hits:
            problems.append(f"missing expected finding '{exp.id}': {exp.description} not found in {exp.report}")
        claimed.update(id(f) for f in hits)

    unexpected: list[Finding] = []
    notes: list[Finding] = []
    for findings in reports.values():
        for f in findings:
            if id(f) in claimed:
                continue
            if str(f.get("id", "")).upper() in allowed or allowed & _identifier_values(f):
                print(f"note: accepted/allowed extra finding: {_describe(f)}")
                continue
            blocking = strict or str(f.get("severity", "")).lower() in BLOCKING_SEVERITIES
            (unexpected if blocking else notes).append(f)

    if unexpected:
        label = "finding(s)" if strict else "High/Critical finding(s)"
        problems.append(f"{len(unexpected)} unexpected {label}:")
        problems.extend(f"    - {_describe(f)}" for f in unexpected)

    if problems:
        raise FindingsMismatch("findings do not match docs/EXPECTED_FINDINGS.md:\n  " + "\n  ".join(problems))

    for f in notes:
        print(f"note: tolerated lower-severity extra finding: {_describe(f)}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--report-dir", default=".", help="directory holding the gl-*-report.json files (default: .)")
    ap.add_argument("--strict", action="store_true", help="fail on ANY extra finding, not just High/Critical")
    ap.add_argument("--allow", action="append", default=[], metavar="ID",
                    help="extra finding id / CVE to ignore, in addition to the built-in "
                         "ACCEPTED_TRANSITIVE list (repeatable)")
    args = ap.parse_args(argv)
    try:
        verify_findings(args.report_dir, strict=args.strict, allow=tuple(args.allow))
    except FindingsMismatch as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print("OK: exactly the 3 planted findings are present "
          "(sql-injection, hardcoded-secret, vulnerable-dependency); no unexpected High/Critical findings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
