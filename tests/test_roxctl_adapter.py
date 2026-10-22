"""Tests for scripts/roxctl_to_gl_depscan.py (ACS roxctl JSON -> GitLab report).

Uses a synthetic roxctl-shaped scan: the planted python-jose CVE (language-level,
must be kept) alongside a base-image OS CVE (must be dropped by default).
"""
from scripts.roxctl_to_gl_depscan import convert

ROXCTL_SAMPLE = {
    "scan": {
        "components": [
            {
                "name": "python-jose",
                "version": "3.3.0",
                "source": "PYTHON",
                "vulns": [
                    {"cve": "CVE-2024-33663", "severity": "IMPORTANT_VULNERABILITY_SEVERITY",
                     "summary": "JWT algorithm confusion", "fixedBy": "3.4.0"},
                ],
            },
            {
                "name": "ecdsa",
                "version": "0.19.0",
                "source": "PYTHON",
                "vulns": [
                    {"cve": "CVE-2024-23342", "severity": "IMPORTANT_VULNERABILITY_SEVERITY",
                     "summary": "Minerva timing attack"},
                ],
            },
            {
                "name": "glibc",
                "version": "2.36",
                "source": "OS",
                "vulns": [
                    {"cve": "CVE-2026-00000", "severity": "CRITICAL_VULNERABILITY_SEVERITY",
                     "summary": "base-image OS CVE that must not reach the gate"},
                ],
            },
        ],
    },
}


def _cves(report):
    out = set()
    for v in report["vulnerabilities"]:
        out.update(i["value"] for i in v["identifiers"])
    return out


def test_keeps_language_findings_and_drops_os():
    report = convert(ROXCTL_SAMPLE)
    cves = _cves(report)
    assert "CVE-2024-33663" in cves          # the planted dependency finding
    assert "CVE-2024-23342" in cves          # transitive ecdsa (accepted elsewhere)
    assert "CVE-2026-00000" not in cves      # base-image OS CVE dropped
    assert report["scan"]["type"] == "dependency_scanning"


def test_severity_and_package_mapping():
    report = convert(ROXCTL_SAMPLE)
    jose = next(v for v in report["vulnerabilities"]
                if v["identifiers"][0]["value"] == "CVE-2024-33663")
    assert jose["severity"] == "High"        # IMPORTANT -> High
    assert jose["location"]["dependency"]["package"]["name"] == "python-jose"
    assert jose["location"]["dependency"]["version"] == "3.3.0"


def test_include_os_flag_keeps_os():
    report = convert(ROXCTL_SAMPLE, include_os=True)
    assert "CVE-2026-00000" in _cves(report)


def test_output_satisfies_verifier_dependency_match():
    # The adapter output must satisfy verify_findings._is_vulnerable_dependency.
    from scripts.verify_findings import _is_vulnerable_dependency
    report = convert(ROXCTL_SAMPLE)
    assert any(_is_vulnerable_dependency(v) for v in report["vulnerabilities"])
