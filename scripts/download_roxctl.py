#!/usr/bin/env python3
"""Download the roxctl CLI from ACS Central (version-matched to the instance).

Central serves its own matching roxctl binary, so downloading it here avoids
pinning a roxctl image version that could drift from the cluster's ACS version.
Pure stdlib (urllib) so it runs in a plain python image with no curl.

Env:
  ROX_ENDPOINT  host:port of ACS Central (required), e.g. central.stackrox.svc:443
  ROX_API_TOKEN API token for Central (required)
  ROX_INSECURE_CLIENT_SKIP_TLS_VERIFY  "true" to skip TLS verification (self-signed Central)

Usage: python scripts/download_roxctl.py ./roxctl
"""
from __future__ import annotations

import os
import ssl
import stat
import sys
import urllib.request


def main(argv: list[str]) -> int:
    out = argv[1] if len(argv) > 1 else "./roxctl"
    endpoint = os.environ.get("ROX_ENDPOINT", "").strip()
    token = os.environ.get("ROX_API_TOKEN", "").strip()
    cafile = os.environ.get("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt").strip()
    if not endpoint or not token:
        print("ERROR: ROX_ENDPOINT and ROX_API_TOKEN must be set", file=sys.stderr)
        return 2

    host = endpoint if "://" in endpoint else f"https://{endpoint}"
    url = f"{host}/api/cli/download/roxctl-linux-amd64"

    ctx = ssl.create_default_context(cafile=cafile)
    if os.environ.get("ROX_INSECURE_CLIENT_SKIP_TLS_VERIFY", "").lower() == "true":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    print(f"Downloading roxctl from {url}")
    with urllib.request.urlopen(req, context=ctx, timeout=120) as resp, open(out, "wb") as fh:
        fh.write(resp.read())
    os.chmod(out, os.stat(out).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
