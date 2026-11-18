#!/usr/bin/env python3
"""Publishes a signed endpoint-agent release (docs/specs/agent-update-SPEC.md). Run by the operator on the platform VM.

    BAO_TOKEN=<token able to sign with agent-release> python3 infra/agent-release/publish.py <installer.msi> <version> [--state PRODUCTION]

What it does:
  1. reads the installer and computes its SHA-256;
  2. asks OpenBao to sign the release statement with the `agent-release` key (the private key never leaves OpenBao);
  3. uploads installer + hash + signature to iam-tenant-svc's internal publish route.
The agent re-checks everything itself, so this tool is a convenience, not a trust point: a wrong hash or an unsigned file is
refused by the agents whatever this script sends.

--dry-run signs and prints the JSON (without the installer bytes) and uploads nothing.

Environment: BAO_TOKEN (required, never printed), BAO_ADDR (default http://127.0.0.1:8200), PUBLISH_VIA (default
`sudo docker exec -i iam_core_platform-iam-auth-svc-1 curl`, a container on the platform network, so the call does not pass the
public proxy; the route answers 404 to anything that did).
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

KEY_NAME = "agent-release"
PLATFORM = "WINDOWS"
ARCHITECTURE = "x86_64"
STATEMENT_LABEL = "iam-agent-release-v1"
VERSION_RE = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,6}$")
MAX_BYTES = 64 * 1024 * 1024
PUBLISH_URL = "http://iam-tenant-svc:8080/internal/agent-releases"


def statement(platform: str, architecture: str, version: str, sha256_hex: str) -> str:
    """The exact text signed. MUST match update.rs `release_statement` and AgentReleases.kt."""
    return "\n".join([STATEMENT_LABEL, platform, architecture, version, sha256_hex])


def build_payload(content: bytes, version: str, signature: str, state: str) -> dict:
    return {
        "version": version,
        "platform": PLATFORM,
        "architecture": ARCHITECTURE,
        "sha256": hashlib.sha256(content).hexdigest(),
        "signature": signature,
        "releaseState": state,
        "contentBase64": base64.b64encode(content).decode(),
    }


def sign(token: str, text: str) -> str:
    request = urllib.request.Request(
        os.environ.get("BAO_ADDR", "http://127.0.0.1:8200").rstrip("/") + f"/v1/transit/sign/{KEY_NAME}",
        data=json.dumps({"input": base64.b64encode(text.encode()).decode()}).encode(),
        method="POST",
        headers={"X-Vault-Token": token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read())["data"]["signature"]
    except urllib.error.HTTPError as error:
        sys.exit(f"OpenBao refused to sign (HTTP {error.code}). Does this token allow signing with '{KEY_NAME}'? Has agent-release-setup.py been run?")
    except urllib.error.URLError as error:
        sys.exit(f"Cannot reach OpenBao: {error.reason}")


def upload(payload: dict) -> None:
    # `sudo`: the operator's normal account is not in the docker group (found on the real VM, 2026-11-18).
    command = os.environ.get("PUBLISH_VIA", "sudo docker exec -i iam_core_platform-iam-auth-svc-1 curl").split()
    result = subprocess.run(
        command + ["-s", "-m", "120", "-w", "\n%{http_code}", "-X", "POST", "-H", "Content-Type: application/json", "--data-binary", "@-", PUBLISH_URL],
        input=json.dumps(payload).encode(),
        capture_output=True,
    )
    out = result.stdout.decode(errors="replace").rsplit("\n", 1)
    body, code = (out[0], out[1].strip()) if len(out) == 2 else (result.stdout.decode(errors="replace"), "?")
    if code != "201":
        # Show WHY. An empty "HTTP ?" with no explanation hid the real cause once (docker permission denied).
        problem = result.stderr.decode(errors="replace").strip()[:300] or body[:300] or "no response"
        sys.exit(f"upload refused (HTTP {code}): {problem}")
    print("published:", body[:300])


def main(argv: list) -> None:
    args = [a for a in argv if not a.startswith("--")]
    dry = "--dry-run" in argv
    state = "PRODUCTION"
    if "--state" in argv:
        state = argv[argv.index("--state") + 1]
        args = [a for a in args if a != state]
    if len(args) != 2:
        sys.exit(__doc__)
    path, version = args
    if not VERSION_RE.match(version):
        sys.exit(f"version {version!r} must look like 1.2.3")
    if state not in ("DRAFT", "PILOT", "PRODUCTION", "RETIRED"):
        sys.exit("--state must be DRAFT, PILOT, PRODUCTION or RETIRED")
    if not path.lower().endswith(".msi") or not os.path.isfile(path):
        sys.exit(f"{path!r} is not an .msi file")
    content = open(path, "rb").read()
    if not 0 < len(content) <= MAX_BYTES:
        sys.exit(f"installer size {len(content)} is not acceptable")
    token = os.environ.get("BAO_TOKEN", "").strip()
    if not token:
        sys.exit("set BAO_TOKEN to a token allowed to sign with the agent-release key (it is not printed)")

    sha = hashlib.sha256(content).hexdigest()
    signature = sign(token, statement(PLATFORM, ARCHITECTURE, version, sha))
    payload = build_payload(content, version, signature, state)
    print(f"version {version}  sha256 {sha}  {len(content)} bytes  state {state}")
    if dry:
        shown = dict(payload, contentBase64=f"<{len(content)} bytes omitted>")
        print(json.dumps(shown, indent=2))
        return
    upload(payload)


if __name__ == "__main__":
    main(sys.argv[1:])
