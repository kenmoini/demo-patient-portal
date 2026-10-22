#!/usr/bin/env python3
"""Convert `roxctl image scan --output json` into a GitLab dependency-scanning report.

ACS (Red Hat Advanced Cluster Security) is this cluster's scanner; on GitLab Free
the managed Dependency Scanning feature is unavailable, so we scan the built image
with ACS via roxctl and adapt its output into the gl-dependency-scanning-report.json
schema that scripts/verify_findings.py consumes.

roxctl's JSON (observed on ACS 4.x) is a FLAT list:

    {"result": {"summary": {...},
                "vulnerabilities": [
                    {"cveId": "CVE-2024-33663", "cveSeverity": "CRITICAL",
                     "cveInfo": "https://...", "componentName": "python-jose",
                     "componentVersion": "3.3.0", "componentFixedVersion": "3.4.0"}, ...]}}

An image scan reports the WHOLE image (OS base layer + every installed package),
and roxctl's flat output has no OS-vs-language marker. So by default this adapter
keeps only components declared in requirements.txt (pass --requirements), which
drops base-image OS CVEs and leaves the application dependency surface — including
the planted python-jose finding. Pass --all to keep everything.

Pure stdlib. Parsing is defensive: it reads the flat `result.vulnerabilities`
shape, an older `scan.components[].vulns` shape, or walks for CVE-bearing records;
if it extracts nothing it prints the JSON's top-level keys to aid diagnosis.

Usage: roxctl_to_gl_depscan.py <roxctl-scan.json> <out.json> [--requirements PATH] [--all]
"""
from __future__ import annotations

import json
import re
import sys

# Severity: roxctl short forms AND the longer StackRox enum -> GitLab severity.
SEVERITY_MAP = {
    "CRITICAL": "Critical", "IMPORTANT": "High", "MODERATE": "Medium", "LOW": "Low",
    "UNKNOWN": "Unknown",
    "CRITICAL_VULNERABILITY_SEVERITY": "Critical",
    "IMPORTANT_VULNERABILITY_SEVERITY": "High",
    "MODERATE_VULNERABILITY_SEVERITY": "Medium",
    "LOW_VULNERABILITY_SEVERITY": "Low",
}


def _norm_pkg(name: str) -> str:
    """PyPI-style normalization: lowercase, drop extras, unify -/_/. separators."""
    name = re.split(r"[\[ ;]", str(name).strip(), maxsplit=1)[0]
    return re.sub(r"[-_.]+", "-", name.lower())


def load_requirements(path: str) -> set[str]:
    out: set[str] = set()
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        pkg = re.split(r"[=<>!~ ;\[]", line, maxsplit=1)[0].strip()
        if pkg:
            out.add(_norm_pkg(pkg))
    return out


def _first(d: dict, *keys, default=None):
    for k in keys:
        v = d.get(k)
        if v not in (None, "", []):
            return v
    return default


def _norm_severity(raw) -> str:
    s = str(raw or "").upper()
    return SEVERITY_MAP.get(s, (str(raw).capitalize() if raw else "Unknown"))


def _records(doc) -> list[tuple[str, str, str, str, str]]:
    """Return (cve, component, version, severity, link) tuples across roxctl shapes."""
    recs: list[tuple[str, str, str, str, str]] = []

    # Flat shape: result.vulnerabilities[] (observed on ACS 4.x).
    result = doc.get("result") if isinstance(doc, dict) else None
    flat = (result or {}).get("vulnerabilities") if isinstance(result, dict) else None
    if isinstance(flat, list) and flat and isinstance(flat[0], dict) and "componentName" in flat[0]:
        for v in flat:
            cve = _first(v, "cveId", "cve", "id", "name")
            if cve:
                recs.append((cve, _first(v, "componentName", default="unknown"),
                             str(_first(v, "componentVersion", default="")),
                             _norm_severity(_first(v, "cveSeverity", "severity")),
                             _first(v, "cveInfo", "link", "url", default="")))
        return recs

    # Older component shape: scan.components[].vulns[]
    scan = doc.get("scan") if isinstance(doc, dict) else None
    comps = (scan or {}).get("components") if isinstance(scan, dict) else None
    if isinstance(comps, list):
        for c in comps:
            name, ver = _first(c, "name", default="unknown"), str(_first(c, "version", default=""))
            for v in _first(c, "vulns", "vulnerabilities", default=[]) or []:
                cve = _first(v, "cve", "cveId", "id", "name")
                if cve:
                    recs.append((cve, name, ver, _norm_severity(_first(v, "severity", "cveSeverity")),
                                 _first(v, "link", "url", default="")))
        return recs

    # Defensive: walk for any dict carrying a cve-ish key.
    def walk(node):
        if isinstance(node, dict):
            cve = _first(node, "cveId", "cve")
            if cve and _first(node, "componentName", "name"):
                recs.append((cve, _first(node, "componentName", "name", default="unknown"),
                             str(_first(node, "componentVersion", "version", default="")),
                             _norm_severity(_first(node, "cveSeverity", "severity")),
                             _first(node, "cveInfo", "link", "url", default="")))
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(doc)
    return recs


def convert(doc: dict, declared: set[str] | None = None, include_all: bool = False) -> dict:
    vulns = []
    for cve, comp, ver, severity, link in _records(doc):
        if declared is not None and not include_all and _norm_pkg(comp) not in declared:
            continue  # drop OS / base-image packages not declared in requirements.txt
        vulns.append({
            "id": f"{comp}:{cve}",
            "category": "dependency_scanning",
            "name": f"{cve} in {comp}",
            "severity": severity,
            "location": {"file": "image",
                         "dependency": {"package": {"name": comp}, "version": ver}},
            "identifiers": [{"type": "cve", "name": cve, "value": cve,
                             "url": link or f"https://nvd.nist.gov/vuln/detail/{cve}"}],
        })
    return {
        "version": "15.0.0",
        "scan": {
            "analyzer": {"id": "roxctl", "name": "roxctl (ACS adapter)", "version": "1",
                         "vendor": {"name": "Red Hat ACS"}},
            "scanner": {"id": "acs-scanner", "name": "ACS Scanner", "version": "v4",
                        "vendor": {"name": "Red Hat ACS"}},
            "type": "dependency_scanning", "status": "success",
        },
        "vulnerabilities": vulns,
    }


def main(argv: list[str]) -> int:
    include_all = "--all" in argv
    declared = None
    req_path = None
    if "--requirements" in argv:
        req_path = argv[argv.index("--requirements") + 1]
        declared = load_requirements(req_path)
    # Positionals = args that are neither a flag nor the value consumed by --requirements.
    pos = [a for a in argv[1:] if not a.startswith("--") and a != req_path]
    if len(pos) != 2:
        print("usage: roxctl_to_gl_depscan.py <in.json> <out.json> "
              "[--requirements PATH] [--all]", file=sys.stderr)
        return 2
    src, dst = pos
    doc = json.loads(open(src, encoding="utf-8").read())
    report = convert(doc, declared=declared, include_all=include_all)
    with open(dst, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    n = len(report["vulnerabilities"])
    scope = "all components" if (declared is None or include_all) else "declared deps only"
    print(f"Wrote {dst}: {n} finding(s) ({scope}).")
    if n == 0:
        top = list(doc.keys()) if isinstance(doc, dict) else type(doc).__name__
        print(f"WARNING: no findings extracted. roxctl JSON top-level: {top}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
