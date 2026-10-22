"""Tests for scripts/roxctl_to_gl_depscan.py (ACS roxctl JSON -> GitLab report).

Uses the real flat roxctl shape (result.vulnerabilities[]) observed on ACS 4.x:
the planted python-jose CVE (declared dep, kept) + a 2nd python-jose critical
(kept) + a base-image OS CVE on a package not in requirements.txt (dropped).
"""
from scripts.roxctl_to_gl_depscan import convert, load_requirements

# Mirrors the real `roxctl image scan --output json` structure.
ROXCTL_SAMPLE = {
    "result": {
        "summary": {"CRITICAL": 2, "IMPORTANT": 0, "LOW": 1, "TOTAL-VULNERABILITIES": 3},
        "vulnerabilities": [
            {"cveId": "CVE-2024-33663", "cveSeverity": "CRITICAL", "cveCVSS": 0,
             "cveInfo": "https://nvd.nist.gov/vuln/detail/CVE-2024-33663",
             "componentName": "python-jose", "componentVersion": "3.3.0",
             "componentFixedVersion": "3.4.0"},
            {"cveId": "CVE-2026-85394", "cveSeverity": "CRITICAL", "cveCVSS": 0,
             "cveInfo": "https://nvd.nist.gov/vuln/detail/CVE-2026-85394",
             "componentName": "python-jose", "componentVersion": "3.3.0",
             "componentFixedVersion": ""},
            {"cveId": "CVE-2026-00001", "cveSeverity": "LOW", "cveCVSS": 0,
             "cveInfo": "", "componentName": "libc6", "componentVersion": "2.36",
             "componentFixedVersion": ""},  # base-image OS package (not in requirements.txt)
        ],
    },
}

DECLARED = {"python-jose", "fastapi", "jinja2"}  # a sample requirements closure


def _cves(report):
    return {i["value"] for v in report["vulnerabilities"] for i in v["identifiers"]}


def test_parses_flat_result_shape():
    report = convert(ROXCTL_SAMPLE)  # no filter -> all records parsed
    assert "CVE-2024-33663" in _cves(report)
    assert report["scan"]["type"] == "dependency_scanning"


def test_declared_filter_drops_os_keeps_app_deps():
    report = convert(ROXCTL_SAMPLE, declared=DECLARED)
    cves = _cves(report)
    assert "CVE-2024-33663" in cves     # python-jose: declared, kept
    assert "CVE-2026-85394" in cves     # 2nd python-jose CVE: kept
    assert "CVE-2026-00001" not in cves  # libc6: OS, not declared, dropped


def test_severity_and_package_mapping():
    report = convert(ROXCTL_SAMPLE, declared=DECLARED)
    jose = next(v for v in report["vulnerabilities"]
                if v["identifiers"][0]["value"] == "CVE-2024-33663")
    assert jose["severity"] == "Critical"
    assert jose["location"]["dependency"]["package"]["name"] == "python-jose"
    assert jose["location"]["dependency"]["version"] == "3.3.0"


def test_include_all_keeps_os():
    report = convert(ROXCTL_SAMPLE, declared=DECLARED, include_all=True)
    assert "CVE-2026-00001" in _cves(report)


def test_output_satisfies_verifier_dependency_match():
    from scripts.verify_findings import _is_vulnerable_dependency
    report = convert(ROXCTL_SAMPLE, declared=DECLARED)
    assert any(_is_vulnerable_dependency(v) for v in report["vulnerabilities"])


def test_load_requirements_normalizes(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("python-jose==3.3.0\nuvicorn[standard]==0.54.0\n# comment\n\nFaker==40.43.0\n")
    names = load_requirements(str(req))
    assert {"python-jose", "uvicorn", "faker"} <= names
