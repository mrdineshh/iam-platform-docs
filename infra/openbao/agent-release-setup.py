#!/usr/bin/env python3
"""Creates the OpenBao key that signs endpoint-agent releases. Safe to run more than once.

What it does (and nothing else):
  1. Enables the `transit` secrets engine, if it is not already enabled.
  2. Creates an Ed25519 signing key named `agent-release`, if it does not exist.
  3. Signs and verifies a test message with it, then prints the PUBLIC key to put in the agents' config as
     `release_public_key_base64` (the MSI build takes it as -ReleaseKey).

What it deliberately does NOT do: it grants NO permission on this key to any service policy. Laptops will install, as
SYSTEM, whatever this key signs, so only the operator (with their own token, at publish time) may sign. If this key were
added to the shared `cert-issuer` policy, a compromise of iam-tenant-svc or any other service could mint an update that every
laptop accepts. Do not add it there. The script also checks that and refuses to finish if the key IS already reachable
through `cert-issuer`.

Usage (on the server, with a token allowed to manage mounts and keys, e.g. the root token):

    BAO_TOKEN=<token> python3 infra/openbao/agent-release-setup.py

Environment: BAO_TOKEN (required, never printed), BAO_ADDR (default http://127.0.0.1:8200).
Exit code 0 only if every step succeeded.
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.request

KEY_NAME = "agent-release"
SERVICE_POLICY = "cert-issuer"


def policy_grants_key(policy: str) -> bool:
    """True if a policy text mentions signing with this key (path or a wildcard that would cover it). Pure."""
    for line in policy.splitlines():
        line = line.strip()
        if not line.startswith("path"):
            continue
        quoted = line.split('"')
        if len(quoted) < 2:
            continue
        path = quoted[1]
        if not path.startswith("transit/"):
            continue
        if path == f"transit/sign/{KEY_NAME}" or path in ("transit/*", "transit/sign/*") or path.startswith(f"transit/sign/{KEY_NAME}/"):
            return True
        if path.endswith("*") and f"transit/sign/{KEY_NAME}".startswith(path[:-1]):
            return True
    return False


def call(method: str, path: str, token: str, body=None):
    request = urllib.request.Request(
        os.environ.get("BAO_ADDR", "http://127.0.0.1:8200").rstrip("/") + path,
        data=None if body is None else json.dumps(body).encode(),
        method=method,
        headers={"X-Vault-Token": token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, json.loads(raw) if raw else {}
        except ValueError:
            return error.code, {"raw": raw.decode(errors="replace")[:200]}
    except urllib.error.URLError as error:
        sys.exit(f"Cannot reach OpenBao at {os.environ.get('BAO_ADDR', 'http://127.0.0.1:8200')}: {error.reason}")


def fail(message: str):
    sys.exit(f"FAILED: {message}")


def main() -> None:
    token = os.environ.get("BAO_TOKEN", "").strip()
    if not token:
        fail("set BAO_TOKEN to a token that can manage mounts and keys (it is not printed)")

    status, health = call("GET", "/v1/sys/seal-status", token)
    if status != 200:
        fail(f"could not read OpenBao status (HTTP {status})")
    if health.get("sealed"):
        fail("OpenBao is sealed: unseal it first")

    status, mounts = call("GET", "/v1/sys/mounts", token)
    if status != 200:
        fail(f"could not list secrets engines (HTTP {status}): is this token allowed to?")
    if "transit/" in mounts.get("data", mounts):
        print("transit engine: already enabled")
    else:
        status, body = call("POST", "/v1/sys/mounts/transit", token, {"type": "transit"})
        if status not in (200, 204):
            fail(f"could not enable the transit engine (HTTP {status}): {body}")
        print("transit engine: enabled")

    status, key = call("GET", f"/v1/transit/keys/{KEY_NAME}", token)
    if status == 404:
        status, body = call("POST", f"/v1/transit/keys/{KEY_NAME}", token, {"type": "ed25519"})
        if status not in (200, 204):
            fail(f"could not create the signing key (HTTP {status}): {body}")
        status, key = call("GET", f"/v1/transit/keys/{KEY_NAME}", token)
        print(f"signing key '{KEY_NAME}': created (Ed25519)")
    else:
        print(f"signing key '{KEY_NAME}': already exists")
    if status != 200:
        fail(f"could not read the signing key (HTTP {status})")
    data = key["data"]
    if data.get("type") != "ed25519":
        fail(f"key '{KEY_NAME}' exists but is type {data.get('type')!r}, not ed25519: agents cannot verify it")
    public_key = data["keys"][str(data["latest_version"])]["public_key"]
    if len(base64.b64decode(public_key)) != 32:
        fail("the public key is not a raw 32-byte Ed25519 key")

    # The point of a SEPARATE key: no service may be able to sign with it.
    status, current = call("GET", f"/v1/sys/policies/acl/{SERVICE_POLICY}", token)
    if status == 200 and policy_grants_key(current["data"]["policy"]):
        fail(f"the shared '{SERVICE_POLICY}' policy lets services sign with '{KEY_NAME}'. Remove that permission: laptops install what this key signs")
    print(f"policy '{SERVICE_POLICY}': does not allow signing with '{KEY_NAME}' (correct)")

    message = base64.b64encode(b"iam agent-release setup check").decode()
    status, signed = call("POST", f"/v1/transit/sign/{KEY_NAME}", token, {"input": message})
    if status != 200:
        fail(f"test signature failed (HTTP {status}): {signed}")
    status, checked = call("POST", f"/v1/transit/verify/{KEY_NAME}", token, {"input": message, "signature": signed["data"]["signature"]})
    if status != 200 or not checked["data"].get("valid"):
        fail("the test signature did not verify")
    print("test signature: signed and verified")

    print()
    print("Done. Build the installer with this PUBLIC key (safe to share):")
    print(f'  "release_public_key_base64": "{public_key}"')


if __name__ == "__main__":
    main()
