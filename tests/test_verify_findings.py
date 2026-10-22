"""Tests for scripts/verify_findings.py against committed SAMPLE GitLab reports.

The fixtures under tests/fixtures/ are hand-authored, synthetic, minimal
GitLab security-report JSON (no real scanner output, no real secrets).
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.verify_findings import FindingsMismatch, verify_findings

FIXTURES = Path(__file__).parent / "fixtures"
SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_findings.py"

SAST = "gl-sast-report.json"
SECRET = "gl-secret-detection-report.json"
DEPS = "gl-dependency-scanning-report.json"


def _copy_good(tmp_path: Path) -> Path:
    dest = tmp_path / "reports"
    shutil.copytree(FIXTURES / "good", dest)
    return dest


def _mutate(report_dir: Path, name: str, fn) -> None:
    path = report_dir / name
    data = json.loads(path.read_text())
    fn(data["vulnerabilities"])
    path.write_text(json.dumps(data))


def test_good_set_passes():
    # exactly the three planted findings -> no exception
    assert verify_findings(FIXTURES / "good") is None


def test_lower_severity_noise_is_tolerated():
    # extra Low/Medium findings and a same-package companion CVE do not fail the gate
    assert verify_findings(FIXTURES / "tolerated_noise") is None


def test_missing_secret_fails():
    with pytest.raises(FindingsMismatch, match="hardcoded-secret"):
        verify_findings(FIXTURES / "missing_secret")


def test_unexpected_extra_high_finding_fails():
    with pytest.raises(FindingsMismatch, match="unexpected"):
        verify_findings(FIXTURES / "extra_high")


def test_missing_sqli_fails(tmp_path):
    d = _copy_good(tmp_path)
    _mutate(d, SAST, lambda v: v.clear())
    with pytest.raises(FindingsMismatch, match="sql-injection"):
        verify_findings(d)


def test_missing_dependency_fails(tmp_path):
    d = _copy_good(tmp_path)
    _mutate(d, DEPS, lambda v: v.clear())
    with pytest.raises(FindingsMismatch, match="vulnerable-dependency"):
        verify_findings(d)


def _set_semgrep_oss_sqli(vulns):
    """Replace the SAST SQLi entry with the real Semgrep-OSS --gitlab-sast shape:
    identified by the rule id (namespaced), with NO CWE/B608 identifier."""
    vulns.clear()
    vulns.append({
        "id": "semgrep-oss-0001",
        "category": "sast",
        "name": "SQL injection via f-string in sqlalchemy text()",
        "severity": "High",
        "location": {"file": "app/routers/patients_api.py", "start_line": 58},
        "identifiers": [{
            "type": "semgrep_type",
            "name": "Semgrep - ci.semgrep.sqli.sqlalchemy-text-fstring-sql-injection",
            "value": "ci.semgrep.sqli.sqlalchemy-text-fstring-sql-injection",
        }],
    })


def test_semgrep_oss_rule_id_satisfies_sqli(tmp_path):
    # The production SAST report (Semgrep OSS) matches by rule id, not CWE.
    d = _copy_good(tmp_path)
    _mutate(d, SAST, _set_semgrep_oss_sqli)
    assert verify_findings(d) is None


def test_missing_report_file_fails(tmp_path):
    d = _copy_good(tmp_path)
    (d / SECRET).unlink()
    with pytest.raises(FindingsMismatch, match="gl-secret-detection-report.json"):
        verify_findings(d)


def test_extra_dependency_findings_are_informational(tmp_path):
    # ACS image-scanning surfaces CVEs the fixture does not control (OS base image,
    # and extra CVEs on the planted package — e.g. a 2nd python-jose critical).
    # Dependency extras are informational, not fatal; only SAST/Secret extras fail.
    # The planted CVE-2024-33663 must still be present (asserted elsewhere).
    d = _copy_good(tmp_path)

    def add(v):
        for cve, pkg, sev in [
            ("CVE-2026-85394", "python-jose", "Critical"),  # 2nd CVE on planted package
            ("CVE-2099-0001", "left-pad", "Critical"),       # unrelated image dependency
        ]:
            extra = json.loads(json.dumps(v[0]))
            extra["id"] = f"extra-{cve}"
            extra["severity"] = sev
            extra["identifiers"] = [{"type": "cve", "name": cve, "value": cve}]
            extra["location"]["dependency"]["package"]["name"] = pkg
            v.append(extra)

    _mutate(d, DEPS, add)
    assert verify_findings(d) is None


def test_same_file_but_wrong_cwe_does_not_satisfy_sqli(tmp_path):
    # a High finding in patients_api.py that is NOT SQLi must not count as the SQLi
    d = _copy_good(tmp_path)

    def swap(v):
        v[0]["identifiers"] = [{"type": "cwe", "name": "CWE-79", "value": "79"}]

    _mutate(d, SAST, swap)
    with pytest.raises(FindingsMismatch) as exc:
        verify_findings(d)
    assert "sql-injection" in str(exc.value)


def _add_dep_finding(report_dir: Path, *, cve: str, package: str, severity: str) -> None:
    def add(v):
        extra = json.loads(json.dumps(v[0]))
        extra["id"] = f"extra-{cve}"
        extra["severity"] = severity
        extra["identifiers"] = [{"type": "cve", "name": cve, "value": cve}]
        extra["location"]["dependency"]["package"]["name"] = package
        v.append(extra)

    _mutate(report_dir, DEPS, add)


def test_transitive_and_extra_dep_cves_do_not_fail_gate(tmp_path):
    # Transitive (ecdsa) and other image-dependency CVEs are informational under
    # image scanning; they must not fail the gate.
    d = _copy_good(tmp_path)
    _add_dep_finding(d, cve="CVE-2024-23342", package="ecdsa", severity="High")
    _add_dep_finding(d, cve="CVE-2099-54321", package="some-transitive", severity="Critical")
    assert verify_findings(d) is None


def test_cli_passes_with_extra_dependency_finding(tmp_path):
    d = _copy_good(tmp_path)
    _add_dep_finding(d, cve="CVE-2024-23342", package="ecdsa", severity="High")
    r = _run_cli(d)
    assert r.returncode == 0, r.stderr


def _run_cli(report_dir: Path):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--report-dir", str(report_dir)],
        capture_output=True,
        text=True,
    )


def test_cli_exit_zero_on_good():
    r = _run_cli(FIXTURES / "good")
    assert r.returncode == 0, r.stderr
    assert "OK" in r.stdout


def test_cli_exit_nonzero_on_mismatch():
    r = _run_cli(FIXTURES / "extra_high")
    assert r.returncode == 1
    assert "unexpected" in r.stderr
