#!/usr/bin/env python3
"""Sets up OpenBao for Endpoint Device Trust policy signing. Safe to run more than once.

What it does (and nothing else):
  1. Enables the `transit` secrets engine, if it is not already enabled.
  2. Creates an Ed25519 signing key named `device-policy`, if it does not exist. The private key never leaves
     OpenBao: iam-tenant-svc asks OpenBao to sign each device policy and the endpoint agents verify it with the
     matching PUBLIC key.
  3. ADDS permission to sign with that one key to the existing `cert-issuer` policy. It reads the current policy
     and appends to it; it never replaces it, because every service shares that policy and replacing it would
     cut them off from their secrets.
  4. Signs and verifies a test message to prove the key works, then prints the public key to put in each
     agent's config.json as `device_policy_public_key_base64`.

It does NOT touch PKI, certificates, or any other secret.

Usage (on the server, with a token allowed to manage mounts, keys and policies, e.g. the root token):

    BAO_TOKEN=<token> python3 infra/openbao/device-trust-setup.py

Environment: BAO_TOKEN (required, never printed), BAO_ADDR (default http://127.0.0.1:8200).
Exit code 0 only if every step succeeded.
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.request

KEY_NAME = "device-policy"
POLICY_NAME = "cert-issuer"
SIGN_STANZA = f'path "transit/sign/{KEY_NAME}" {{\n  capabilities = ["update"]\n}}\n'


def with_signing_permission(policy: str) -> tuple[str, bool]:
    """Returns (policy, changed): the policy with the signing stanza added if it was missing. Pure: everything
    already in `policy` is preserved byte for byte, and running it again changes nothing."""
    if f'path "transit/sign/{KEY_NAME}"' in policy:
        return policy, False
    return policy.rstrip("\n") + "\n\n" + SIGN_STANZA, True


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
        fail("set BAO_TOKEN to a token that can manage mounts, keys and policies (it is not printed)")

    status, health = call("GET", "/v1/sys/seal-status", token)
    if status != 200:
        fail(f"could not read OpenBao status (HTTP {status})")
    if health.get("sealed"):
        fail("OpenBao is sealed: unseal it first")

    # 1. transit engine
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

    # 2. signing key
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
    latest = str(data["latest_version"])
    public_key = data["keys"][latest]["public_key"]
    if len(base64.b64decode(public_key)) != 32:
        fail("the public key is not a raw 32-byte Ed25519 key")

    # 3. permission for the services' shared role -- read, append, write back (never replace)
    status, current = call("GET", f"/v1/sys/policies/acl/{POLICY_NAME}", token)
    if status != 200:
        fail(f"could not read the '{POLICY_NAME}' policy (HTTP {status}); it must already exist")
    updated, changed = with_signing_permission(current["data"]["policy"])
    if changed:
        status, body = call("PUT", f"/v1/sys/policies/acl/{POLICY_NAME}", token, {"policy": updated})
        if status not in (200, 204):
            fail(f"could not update the '{POLICY_NAME}' policy (HTTP {status}): {body}")
        print(f"policy '{POLICY_NAME}': added permission to sign with '{KEY_NAME}' (everything else kept)")
    else:
        print(f"policy '{POLICY_NAME}': already allows signing with '{KEY_NAME}'")

    # 4. prove the key works
    message = base64.b64encode(b"iam device-trust setup check").decode()
    status, signed = call("POST", f"/v1/transit/sign/{KEY_NAME}", token, {"input": message})
    if status != 200:
        fail(f"test signature failed (HTTP {status}): {signed}")
    signature = signed["data"]["signature"]
    status, checked = call("POST", f"/v1/transit/verify/{KEY_NAME}", token, {"input": message, "signature": signature})
    if status != 200 or not checked["data"].get("valid"):
        fail("the test signature did not verify")
    print("test signature: signed and verified")

    print()
    print("Done. Put this in each agent's config.json (it is a PUBLIC key, safe to share):")
    print(f'  "device_policy_public_key_base64": "{public_key}"')


if __name__ == "__main__":
    main()
