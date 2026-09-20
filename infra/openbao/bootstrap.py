#!/usr/bin/env python3
"""
Idempotent OpenBao bootstrap: init + unseal, PKI CA + role, AppRole for
service cert issuance and the existing KV secrets. Run once after
`docker compose up -d openbao` and again after any real data reset.

Replaces the manual "-dev" mode (hardcoded dev-root-token, no persistence)
that has repeatedly wiped the password pepper / TOTP DEKs / OIDC signing
key on every Docker Desktop restart -- see docs/DECISIONS.md.

Writes:
  infra/openbao/secrets/init.json   -- unseal key + root token (SENSITIVE, gitignored)
  .env (repo root)                  -- BAO_APPROLE_ROLE_ID / BAO_APPROLE_SECRET_ID
                                        for docker-compose to inject into every service

Deliberately simplified vs. a real production rollout (documented, not
hidden): a single root CA (no intermediate), a 1-of-1 unseal key (real
deployments should use a proper Shamir threshold or cloud KMS auto-unseal),
and one shared AppRole for all services (real deployments would want
per-service AppRoles so a compromised service can't issue certs for another
service's identity).
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

BAO_ADDR = os.environ.get("BAO_ADDR", "http://localhost:8200")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
SECRETS_DIR = os.path.join(SCRIPT_DIR, "secrets")
INIT_FILE = os.path.join(SECRETS_DIR, "init.json")
ENV_FILE = os.path.join(REPO_ROOT, ".env")

# Every service that participates in mTLS -- CN == docker-compose service
# name == the hostname every other service already addresses it by.
# "test-client" is not a real service -- it's a cert issued purely so a
# human (or a script) on the host machine can curl the mandatory-mTLS
# services directly for debugging/fixture setup, the same way plain curl
# always could before this change. See write_test_client_cert().
SERVICE_CNS = [
    "iam-tenant-svc", "iam-geo-svc", "iam-identity-svc", "iam-policy-svc",
    "iam-session-svc", "iam-auth-svc", "iam-device-svc", "iam-enforcement-svc",
    "iam-oidcprovider-svc", "test-client",
]


def call(method, path, token=None, body=None, expect=(200, 204)):
    url = f"{BAO_ADDR}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if token:
        req.add_header("X-Vault-Token", token)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw.decode(errors="replace")}


def wait_for_bao():
    for _ in range(60):
        try:
            urllib.request.urlopen(f"{BAO_ADDR}/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200", timeout=2)
            return
        except Exception:
            time.sleep(2)
    print("OpenBao never became reachable at", BAO_ADDR, file=sys.stderr)
    sys.exit(1)


def init_or_load():
    os.makedirs(SECRETS_DIR, exist_ok=True)
    status, body = call("GET", "/v1/sys/init")
    if body.get("initialized"):
        if not os.path.exists(INIT_FILE):
            print(
                "OpenBao reports already initialized, but",
                INIT_FILE,
                "is missing -- can't unseal or authenticate. If this is a "
                "genuinely fresh environment, the raft volume needs clearing "
                "too; if it isn't, restore the real init.json.",
                file=sys.stderr,
            )
            sys.exit(1)
        with open(INIT_FILE) as f:
            return json.load(f)

    print("Initializing OpenBao (1-of-1 unseal key -- local-dev simplification, see module docstring)...")
    status, body = call("PUT", "/v1/sys/init", body={"secret_shares": 1, "secret_threshold": 1})
    if status != 200:
        print("init failed:", body, file=sys.stderr)
        sys.exit(1)
    init_data = {"unseal_key": body["keys"][0], "root_token": body["root_token"]}
    with open(INIT_FILE, "w") as f:
        json.dump(init_data, f, indent=2)
    print(f"Wrote {INIT_FILE} -- back this up somewhere safe; it's the only copy.")
    return init_data


def unseal_if_needed(unseal_key):
    status, body = call("GET", "/v1/sys/seal-status")
    if body.get("sealed"):
        print("Unsealing...")
        status, body = call("PUT", "/v1/sys/unseal", body={"key": unseal_key})
        if body.get("sealed"):
            print("Still sealed after unseal attempt:", body, file=sys.stderr)
            sys.exit(1)


def ensure_pki(token):
    status, mounts = call("GET", "/v1/sys/mounts", token=token)
    if "pki/" not in mounts:
        print("Enabling PKI secrets engine...")
        status, body = call("POST", "/v1/sys/mounts/pki", token=token, body={"type": "pki"})
        if status not in (200, 204):
            print("enabling pki mount failed:", status, body, file=sys.stderr)
            sys.exit(1)
        status, body = call("POST", "/v1/sys/mounts/pki/tune", token=token, body={"max_lease_ttl": "87600h"})
        if status not in (200, 204):
            print("tuning pki mount failed:", status, body, file=sys.stderr)
            sys.exit(1)

    # CA existence is a separate fact from "is the mount enabled" -- check
    # it directly rather than assuming one implies the other (a mount can
    # exist from a partially-failed prior run with no CA generated yet).
    status, ca_check = call("GET", "/v1/pki/cert/ca", token=token)
    if status != 200 or not ca_check.get("data", {}).get("certificate"):
        print("Generating internal root CA...")
        status, root = call(
            "POST", "/v1/pki/root/generate/internal", token=token,
            body={"common_name": "IAM Platform Internal CA", "ttl": "87600h", "key_bits": 2048},
        )
        if status not in (200, 204):
            print("root CA generation failed:", status, root, file=sys.stderr)
            sys.exit(1)
        print("Generated internal root CA.")
    else:
        print("Root CA already present, skipping generation.")

    status, body = call(
        "POST", "/v1/pki/roles/internal-services", token=token,
        body={
            "allowed_domains": SERVICE_CNS,
            "allow_bare_domains": True,
            "allow_subdomains": False,
            "server_flag": True,
            "client_flag": True,
            "key_type": "rsa",
            "key_bits": 2048,
            # 30 days, not a short-lived real-rotation TTL -- same reasoning
            # as the AppRole token TTL above: no renewal daemon exists here,
            # so a short cert TTL would just mean containers silently start
            # failing mTLS handshakes mid-session once it expires.
            "max_ttl": "720h",
            "ttl": "720h",
        },
    )
    if status not in (200, 204):
        print("creating pki role failed:", status, body, file=sys.stderr)
        sys.exit(1)
    print("PKI role 'internal-services' ensured.")


def ensure_kv(token):
    status, mounts = call("GET", "/v1/sys/mounts", token=token)
    if "secret/" not in mounts:
        print("Enabling KV v2 secrets engine at secret/...")
        status, body = call("POST", "/v1/sys/mounts/secret", token=token, body={"type": "kv-v2"})
        if status not in (200, 204):
            print("enabling kv mount failed:", status, body, file=sys.stderr)
            sys.exit(1)


CERT_ISSUER_POLICY = """
path "pki/issue/internal-services" {
  capabilities = ["create", "update"]
}
path "secret/data/password-pepper" {
  capabilities = ["read", "create", "update"]
}
path "secret/data/totp-dek/*" {
  capabilities = ["read", "create", "update"]
}
path "secret/data/fcm-service-account" {
  capabilities = ["read"]
}
path "secret/data/oidc-signing-key" {
  capabilities = ["read", "create", "update"]
}
"""


def ensure_approle(token):
    status, auths = call("GET", "/v1/sys/auth", token=token)
    if "approle/" not in auths:
        print("Enabling AppRole auth method...")
        status, body = call("POST", "/v1/sys/auth/approle", token=token, body={"type": "approle"})
        if status not in (200, 204):
            print("enabling approle auth failed:", status, body, file=sys.stderr)
            sys.exit(1)

    status, body = call("PUT", "/v1/sys/policies/acl/cert-issuer", token=token, body={"policy": CERT_ISSUER_POLICY})
    if status not in (200, 204):
        print("writing cert-issuer policy failed:", status, body, file=sys.stderr)
        sys.exit(1)

    status, body = call(
        "POST", "/v1/auth/approle/role/cert-issuer", token=token,
        # token_ttl/max_ttl deliberately long (30 days): the KV providers
        # (PasswordPepperProvider, TotpDekProvider, OidcSigningKeyProvider)
        # cache lazily on first real use, which can happen well after
        # container startup -- a short-lived AppRole token would expire
        # before a rarely-hit code path (e.g. a new tenant's first TOTP
        # enrollment) ever reads it. Real production would want short-lived
        # tokens plus in-app renewal logic instead; not implemented here.
        body={"token_policies": "cert-issuer", "token_ttl": "720h", "token_max_ttl": "720h", "secret_id_num_uses": 0},
    )
    if status not in (200, 204):
        print("creating cert-issuer approle failed:", status, body, file=sys.stderr)
        sys.exit(1)

    status, role_id_resp = call("GET", "/v1/auth/approle/role/cert-issuer/role-id", token=token)
    if status != 200:
        print("reading role-id failed:", status, role_id_resp, file=sys.stderr)
        sys.exit(1)
    role_id = role_id_resp["data"]["role_id"]

    status, secret_id_resp = call("POST", "/v1/auth/approle/role/cert-issuer/secret-id", token=token, body={})
    if status != 200:
        print("generating secret-id failed:", status, secret_id_resp, file=sys.stderr)
        sys.exit(1)
    secret_id = secret_id_resp["data"]["secret_id"]

    print("AppRole 'cert-issuer' ensured.")
    return role_id, secret_id


def write_test_client_cert(token):
    """Issues a cert for CN=test-client so a human can curl the
    mandatory-mTLS services (iam-session-svc, iam-geo-svc, iam-identity-svc,
    iam-device-svc) directly, e.g.:
      curl --cert infra/openbao/secrets/test-client/cert.pem \\
           --key infra/openbao/secrets/test-client/key.pem \\
           --cacert infra/openbao/secrets/test-client/ca.pem \\
           https://localhost:8086/actuator/health
    """
    test_dir = os.path.join(SECRETS_DIR, "test-client")
    os.makedirs(test_dir, exist_ok=True)
    status, resp = call(
        "PUT", "/v1/pki/issue/internal-services", token=token,
        body={"common_name": "test-client", "ttl": "720h"},
    )
    if status != 200:
        print("issuing test-client cert failed:", status, resp, file=sys.stderr)
        sys.exit(1)
    data = resp["data"]
    with open(os.path.join(test_dir, "cert.pem"), "w") as f:
        f.write(data["certificate"])
    with open(os.path.join(test_dir, "key.pem"), "w") as f:
        f.write(data["private_key"])
    with open(os.path.join(test_dir, "ca.pem"), "w") as f:
        f.write(data["issuing_ca"])
    print(f"Wrote test-client cert to {test_dir}/ (30-day TTL -- re-run this script to renew).")


def write_env(role_id, secret_id):
    lines = []
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            lines = [
                ln for ln in f.read().splitlines()
                if not ln.startswith("BAO_APPROLE_ROLE_ID=") and not ln.startswith("BAO_APPROLE_SECRET_ID=")
            ]
    lines.append(f"BAO_APPROLE_ROLE_ID={role_id}")
    lines.append(f"BAO_APPROLE_SECRET_ID={secret_id}")
    with open(ENV_FILE, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {ENV_FILE} (BAO_APPROLE_ROLE_ID / BAO_APPROLE_SECRET_ID).")


def main():
    wait_for_bao()
    init_data = init_or_load()
    unseal_if_needed(init_data["unseal_key"])
    token = init_data["root_token"]
    ensure_pki(token)
    ensure_kv(token)
    role_id, secret_id = ensure_approle(token)
    write_env(role_id, secret_id)
    write_test_client_cert(token)
    print("\nOpenBao bootstrap complete. Run `docker compose up -d` for the rest of the stack now.")


if __name__ == "__main__":
    main()
