# iam-endpoint-agent

The Windows endpoint agent for the IAM platform's **Endpoint Device Trust** feature (spec: *IAM Endpoint Device
Trust Technical Specification v1*, Phase 1, Windows only). It registers a device with the platform, keeps a
signed policy for it, and reports its health to the backend (`iam-tenant-svc`, `/api/v1/endpoint/*`).

Rust workspace:

| Crate | Role |
|---|---|
| `crates/agent-core` | Platform-agnostic logic: enrollment, device key, signed-policy verification, offline/failure-mode rules, sync loop. No OS code, so it builds and tests anywhere. |
| `iam-endpoint-agent` | The executable. `platform/windows.rs` is the real Windows adapter (Service Control Manager, `ShellExecuteW`, hardware info); `platform/fallback.rs` exists only so the workspace builds and runs on a non-Windows dev machine. |

## What works today (Windows 10 22H2 / Windows 11)

Tested on a real Windows 11 laptop against the live platform unless marked otherwise.

- **Enrollment**: the user signs in in their normal browser (the agent never sees a password or session token); the agent
  proves it holds its own key and registers. CORPORATE devices are approved automatically, BYOD devices wait for an
  administrator. An unknown `--ownership` value is refused rather than treated as CORPORATE.
- **Re-enrollment** (PDF section 6.3): enrolling an already-registered machine says so and exits with code 3 (installers
  treat that as success). `--reset-enrollment --confirm` forgets the identity so the machine can register again as a new
  device; it refuses while the service is running. The old record stays in the console until an administrator revokes it.
- **Signed policy**: fetched, verified (signature, tenant/device binding, expiry, anti-rollback), cached across restarts.
- **Posture**: BitLocker, antivirus, firewall, TPM, Secure Boot, OS and latest update, every 15 minutes; the server judges
  them (required: BitLocker, antivirus, firewall). Report-only: a non-compliant device is flagged, not blocked.
- **Heartbeat** on the policy's interval, measured from the start of each pass, with backoff and jitter when the platform
  is unreachable. The console marks a device Offline after 15 minutes of silence.
- **Browser sign-in restriction**: Chrome and Edge only accept accounts from `allowed_identity_domains` (enterprise policy,
  no TLS inspection). Google's block of an account outside the list was seen on the test laptop.
- **Tamper detection** of the agent's own program and config: DEGRADED health plus a CRITICAL event until restored.
- **Windows Event Log**: Application log, source `IamEndpointAgent` (1000 started, 1001 tamper detected, 1002 tamper
  cleared, 1003 policy rejected, 1004 clock moved back, 1005 posture failure, 1006 stopped, 1010/1011 browser policy).
- **`--status`**: read-only summary of enrollment, policy, offline behaviour and the local decision.
- **TPM-backed device key** (version 0.2.0+): a NEW enrollment uses a non-exportable TPM key when the machine has one and
  falls back to a software key otherwise; the assurance level is reported. An existing identity keeps its key.
  `--tpm-selftest` (add `--user` without administrator rights) checks the machine's TPM end to end.
- **Device-bound sign-in** (0.2.0+): a local endpoint on 127.0.0.1 lets the company sign-in page prove a sign-in comes from
  this enrolled laptop (see `docs/specs/device-bound-signin-SPEC.md`). It answers only the login page's origin.
- **Signed automatic updates** (0.3.0+): see below. Off unless an administrator puts a release key in the config.

## Not done yet (see `docs/OPEN_QUESTIONS.md`)

Devices enrolled before 0.2.0 still use a **software key** in `state.json`, protected only by the folder's administrators-only
permissions (OQ-17); re-enrol to get a TPM key. No device certificate (OQ-23). Automatic **rollback after a bad update** (a failed
install rolls back by itself, but an update that installs and then misbehaves is not detected). On-device blocking by the offline
modes is deliberately report-only (owner decision 2026-11-18). Firefox, Safari and other identity providers. Uninstall protection.
Code signing: the MSI and exe are **unsigned**, so Windows shows "Unknown publisher".

## Install, use, remove

**MSI (recommended).** `install/build_msi.ps1` builds `dist/IamEndpointAgent-<version>.msi` with the tenant's values as
defaults. Double-click it, or push it silently:

```powershell
msiexec /i IamEndpointAgent-0.1.0.msi /qn TENANT_ID=<uuid> POLICY_KEY=<base64> ALLOWED_DOMAINS=example.com
```

Then the user runs **Start menu > IAM Endpoint Agent > Enroll this device**, signs in, and the service starts. Remove it
from Settings > Apps (or `msiexec /x`); that also removes the browser restriction. The MSI has not yet been installed on a
real machine, so treat the first install as a test (`msiexec /i ... /l*v install.log` keeps a log).

**Script (zip).** `install/build_package.ps1` builds `dist/IamEndpointAgent-Setup.zip`; `install\install.ps1` installs and
enrolls in one step. Use one method or the other on a machine, not both: the MSI cannot install over a service created by
the script (run `install.ps1 -Uninstall` first).

Day to day, from an administrator PowerShell:

| Task | Command |
|---|---|
| Start / stop / check | `Start-Service IamEndpointAgent` / `Stop-Service IamEndpointAgent` / `Get-Service IamEndpointAgent` |
| What the agent knows | `& "C:\Program Files\IamEndpointAgent\iam-endpoint-agent.exe" --status` |
| Register again as a new device | stop the service, then `iam-endpoint-agent.exe --reset-enrollment --confirm`, then enroll |
| Run in a window for debugging | `$env:RUST_LOG="info"; iam-endpoint-agent.exe --console` |

## Build the Windows executable (from Linux, no Windows needed)

```bash
rustup target add x86_64-pc-windows-gnu          # and: apt install gcc-mingw-w64-x86-64
RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-static -C link-arg=-static-libgcc" \
  cargo build --release --target x86_64-pc-windows-gnu -p iam-endpoint-agent
# -> target/x86_64-pc-windows-gnu/release/iam-endpoint-agent.exe
```

The result imports only built-in Windows DLLs; nothing needs to be installed alongside it.

## Automatic updates (signed releases)

The agent installs a new version only if it can prove, by itself, that the release was signed by the operator's `agent-release`
key: the signature over `iam-agent-release-v1 / platform / architecture / version / sha256` verifies against the public key in
its own config, the downloaded file hashes to exactly the signed checksum (checked again from disk), and the version is strictly
newer than the running one (no downgrades). The platform only stores and serves releases; no service can sign one. With no key in
`config.json` (`release_public_key_base64`) updates are off. It checks 5 minutes after start, then every 6 hours, and reports
`agent.update_installing`, `agent.update_rejected` (CRITICAL) or `agent.update_failed` to the console and the Windows Event Log
(ids 1020 to 1022). Specification: `docs/specs/agent-update-SPEC.md`.

**One-time, on the VM** (root token, typed at the prompt; creates the key, grants no service access to it, prints the public key):

```bash
cd /opt/iam/Iam_core_Platform
export BAO_TOKEN=$(sudo python3 -c 'import json;print(json.load(open("infra/openbao/secrets/init.json"))["root_token"])')
python3 infra/openbao/agent-release-setup.py
unset BAO_TOKEN
```

Build the installer with that public key: `install\build_msi.ps1 ... -ReleaseKey "<base64>"`. An upgrade keeps a laptop's
existing config and only adds the key if it is missing (`FORCE_CONFIG=1` on the msiexec line rewrites it on purpose).

**Per release:** build the MSI with a higher version, copy it to the VM, then publish it (root token again, at publish time):

```bash
export BAO_TOKEN=$(sudo python3 -c 'import json;print(json.load(open("infra/openbao/secrets/init.json"))["root_token"])')
python3 infra/agent-release/publish.py /path/to/IamEndpointAgent-0.3.1.msi 0.3.1      # add --dry-run to sign without uploading
unset BAO_TOKEN
```

Laptops pick it up within 6 hours (or 5 minutes after their service starts). `--state PILOT` / `DRAFT` stores a release without
offering it. Offline check of the verifier against a throwaway real OpenBao: see `infra/agent-release/` and `demo/update_e2e.ps1`.

**Why an upgrade cannot remove your agent:** the installer installs the new version FIRST and removes the old one afterwards (`MajorUpgrade Schedule="afterInstallExecute"`). With the default order a failed install made Windows roll back WITHOUT restoring the old version and left the laptop with no agent; that was found with a deliberately failing test installer (`build_msi.ps1 -FailInjection`, never part of a release) and the fix was proven the same way. The config step also never fails an upgrade.

## One-time setup on the platform (so signed policies work)

Without this the agent still enrolls, reports posture and heartbeats, but cannot verify a policy and shows as degraded.
On the VM, as the operator, using the OpenBao root token (type it at the prompt; it is not echoed, stored or printed):

```bash
cd /opt/iam/Iam_core_Platform
read -rs -p "OpenBao token: " BAO_TOKEN; echo; export BAO_TOKEN
python3 infra/openbao/device-trust-setup.py
unset BAO_TOKEN
```

It creates the signing key, adds the one permission the services need, proves it works, and prints the **public** key line
for `config.json`. Safe to run again. It does not touch certificates or any other secret.

## Tests

`cargo test --workspace` (91 tests). The signed-policy format is pinned by a golden vector shared with the Kotlin
backend (`DevicePolicyCanonicalTest` / `policy_verifier::golden_vector_matches_the_backend`), and so is the key
thumbprint algorithm, so the two sides cannot drift apart silently.
