# Spec: signed agent updates (P1-26)

Source: *IAM Endpoint Device Trust Technical Specification v1*, P1-26 "Signed agent updates and rollback", section 16 (signed,
versioned artefacts), section 7 (update-manager). Windows only. Owner decision 2026-11-18: releases are signed by a NEW, separate
OpenBao transit key `agent-release`.

## 1. Trust model (why it is shaped like this)

A laptop installs what this mechanism gives it, **as SYSTEM**. So:

* **Only the operator signs a release**, with the `agent-release` key in OpenBao, using their own token at publish time. No platform
  service has permission to sign releases: a compromised iam-tenant-svc can serve a file but cannot make one the agents accept.
* **The agent decides**, not the server: it installs only if (a) the file's SHA-256 equals the signed checksum, (b) the Ed25519
  signature verifies against `release_public_key_base64` in its own (administrator-only) config, and (c) the signed version is strictly
  newer than its own. (c) stops an attacker replaying an older, validly signed release with a known bug (downgrade).
* No key configured = updates off. The platform cannot turn them on remotely.

## 2. Signed statement

`iam-agent-release-v1\n{platform}\n{architecture}\n{version}\n{sha256-hex-lowercase}`, e.g.
`iam-agent-release-v1\nWINDOWS\nx86_64\n0.3.1\n5f2c...`. Signed by OpenBao transit (Ed25519); stored as the base64 signature (the
`vault:v1:` prefix stripped or tolerated, as for device policies).

## 3. Data

`V13`: `iam_agent_releases.signature TEXT`; new `iam_agent_release_packages (release_id PK FK -> iam_agent_releases ON DELETE CASCADE,
content BYTEA NOT NULL, size_bytes BIGINT NOT NULL)`. Release state `PRODUCTION` is what agents are offered; `DRAFT`/`PILOT`/`RETIRED`
are stored but not offered.

## 4. API

* Internal, operator-only (InternalOnlyFilter: 404 through the public proxy): `POST /internal/agent-releases`
  `{version, platform, architecture, sha256, signature, releaseState, contentBase64}`. The server recomputes the SHA-256 of the content
  and refuses a mismatch. Duplicate (version, platform, architecture) refused.
* Device-authenticated (same signed headers as the policy fetch):
  `GET /api/v1/endpoint/devices/{id}/agent-update?tenantId=&currentVersion=` -> 200 `{releaseId, version, platform, architecture, sha256,
  signature, sizeBytes}` for the newest PRODUCTION release newer than `currentVersion`, else 204.
  `GET /api/v1/endpoint/devices/{id}/agent-releases/{releaseId}/package?tenantId=` -> the MSI bytes.

## 5. Agent

Checks 5 minutes after start, then every 6 hours. On an offer: download to `%ProgramData%\IamEndpointAgent\updates\`, verify (1),
then start `msiexec /i <file> /qn /norestart` detached (the MSI's MajorUpgrade stops the service, replaces it and starts it again).
Events: `agent.update_installing` (INFO), `agent.update_rejected` (CRITICAL, with the reason), to the platform and the Windows Event Log.

**Rollback:** Windows Installer is transactional: a failed upgrade rolls back to the installed version automatically. NOT built: an
automatic return to the previous version when the new one installs fine but then misbehaves (would need the previous MSI kept and a
health watchdog); recorded as a limit.

**Upgrade keeps the existing config.** `configure.ps1` writes `config.json` only on a fresh install, and on an upgrade adds fields that
are missing (such as the release key) without changing existing ones.

## 6. Operator steps

1. Once: create the `agent-release` key (`infra/openbao/agent-release-setup.py`, root token) and put the printed public key in the MSI
   build (`build_msi.ps1 -ReleaseKey`).
2. Per release: build the MSI, then `infra/agent-release/publish.py <msi> <version>` on the VM (root token): hash, sign, upload.

## 7. Success criteria

1. A correctly signed newer release is installed and the agent comes back on the new version.
2. Wrong signature, wrong hash, older or equal version, missing key: refused, nothing run, event raised (unit-tested; signature and hash
   also exercised for real).
3. A service compromise cannot produce an accepted release (no service holds sign permission on `agent-release`).
