#!/usr/bin/env python3
"""Convert `roxctl image scan --output json` into a GitLab dependency-scanning report.

ACS (Red Hat Advanced Cluster Security) is this cluster's scanner; on GitLab Free
the managed Dependency Scanning feature is unavailable, so we scan the built image
with ACS via roxctl and adapt its output into the gl-dependency-scanning-report.json
schema that scripts/verify_findings.py already consumes.

Key behavior: ACS scans the whole image, so it also reports OS/base-image CVEs.
This adapter emits ONLY language-level (application dependency) findings by default
— so base-image Debian/UBI CVEs do not flood the "exactly three planted findings"
gate. Pass --include-os to keep OS findings too.

Pure stdlib (json). The roxctl JSON shape can vary by ACS version, so parsing is
defensive: it locates components by walking the document, reads common field-name
variants, and — if it finds nothing — prints the top-level keys to aid diagnosis.

Usage: python scripts/roxctl_to_gl_depscan.py <roxctl-scan.json> <out.json> [--include-os]
"""
from __future__ import annotations

import json
import sys

# StackRox component "source"/type values that denote OS / base-image packages
# (everything else is treated as a language-level application dependency).
OS_SOURCES = {"OS", "INFRASTRUCTURE", "DOTNET_CORE_RUNTIME_SOURCE", "DOTNETCORERUNTIME"}

# StackRox severity enum -> GitLab severity.
SEVERITY_MAP = {
    "CRITICAL_VULNERABILITY_SEVERITY": "Critical",
    "IMPORTANT_VULNERABILITY_SEVERITY": "High",
    "MODERATE_VULNERABILITY_SEVERITY": "Medium",
    "LOW_VULNERABILITY_SEVERITY": "Low",
    "UNKNOWN_VULNERABILITY_SEVERITY": "Unknown",
}


def _first(d: dict, *keys, default=None):
    for k in keys:
        v = d.get(k)
        if v not in (None, "", []):
            return v
    return default


def _norm_severity(raw) -> str:
    if not raw:
        return "Unknown"
    s = str(raw)
    if s in SEVERITY_MAP:
        return SEVERITY_MAP[s]
    return s.capitalize() if s.islower() else s  # already "High"/"Critical" etc.


def _components(doc) -> list[dict]:
    """Find the component list across roxctl JSON shapes."""
    scan = doc.get("scan") if isinstance(doc, dict) else None
    if isinstance(scan, dict) and isinstance(scan.get("components"), list):
        return scan["components"]
    if isinstance(doc, dict) and isinstance(doc.get("components"), list):
        return doc["components"]
    # Defensive: walk for any dict carrying a vulns/vulnerabilities list.
    found: list[dict] = []

    def walk(node):
        if isinstance(node, dict):
            if isinstance(_first(node, "vulns", "vulnerabilities"), list) and _first(node, "name"):
                found.append(node)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(doc)
    return found


def _is_os(component: dict) -> bool:
    src = str(_first(component, "source", "sourceType", "type", default="")).upper()
    return src in OS_SOURCES


def convert(doc: dict, include_os: bool = False) -> dict:
    vulnerabilities: list[dict] = []
    for comp in _components(doc):
        if not include_os and _is_os(comp):
            continue
        name = _first(comp, "name", default="unknown")
        version = str(_first(comp, "version", default=""))
        for v in _first(comp, "vulns", "vulnerabilities", default=[]) or []:
            cve = _first(v, "cve", "cveId", "id", "name")
            if not cve:
                continue
            severity = _norm_severity(_first(v, "severity", "cvssV3Severity"))
            link = _first(v, "link", "url", default="")
            vulnerabilities.append({
                "id": f"{name}:{cve}",
                "category": "dependency_scanning",
                "name": f"{cve} in {name}",
                "description": str(_first(v, "summary", "description", default="")),
                "severity": severity,
                "location": {
                    "file": "image",
                    "dependency": {"package": {"name": name}, "version": version},
                },
                "identifiers": [{
                    "type": "cve",
                    "name": cve,
                    "value": cve,
                    "url": link or f"https://nvd.nist.gov/vuln/detail/{cve}",
                }],
            })
    return {
        "version": "15.0.0",
        "scan": {
            "analyzer": {"id": "roxctl", "name": "roxctl (ACS adapter)", "version": "1",
                         "vendor": {"name": "Red Hat ACS"}},
            "scanner": {"id": "acs-scanner", "name": "ACS Scanner", "version": "v4",
                        "vendor": {"name": "Red Hat ACS"}},
            "type": "dependency_scanning",
            "status": "success",
        },
        "vulnerabilities": vulnerabilities,
    }


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    include_os = "--include-os" in argv
    if len(args) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    src, dst = args
    doc = json.loads(open(src, encoding="utf-8").read())
    report = convert(doc, include_os=include_os)
    with open(dst, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    n = len(report["vulnerabilities"])
    print(f"Wrote {dst}: {n} language-level finding(s)"
          f"{' (incl. OS)' if include_os else ''}.")
    if n == 0:
        top = list(doc.keys()) if isinstance(doc, dict) else type(doc).__name__
        print(f"WARNING: no findings extracted. Top-level of roxctl JSON: {top}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
