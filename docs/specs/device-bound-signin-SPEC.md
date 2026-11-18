# Spec: device-bound sign-in (P1-12/P1-13) and TPM-backed device keys (P1-06)

Source: *IAM Endpoint Device Trust Technical Specification v1* sections 4.2 (trust decision rule), 5.3 (device keys),
6.2/6.4 (device states, pending-device access), 15.3 (application-specific rules), 16 (security). Windows only.
Status: **design agreed 2026-11-17; implementation in slices, see the checklist at the end.**

## 1. Decisions taken by the owner (2026-11-17)

| # | Question | Decision |
|---|---|---|
| D1 | How a browser sign-in proves it comes from an enrolled laptop | **Agent signed challenge** over a loopback (127.0.0.1) endpoint run by the agent service. Not mTLS (that waits for the certificate work, P1-10). |
| D2 | When device state blocks a sign-in | **Only for apps an admin marks "trusted device required".** Everything else behaves as today. |
| D3 | Device keys | **TPM-backed ECDSA P-256 where a TPM exists, software fallback elsewhere**, assurance level reported either way (spec 5.3). |
| D4 | Non-compliant laptops | **Blocked only from the flagged apps**; visible to the admin with the reason. No automatic suspension. |

## 2. Why this shape (so a later session does not "simplify" it away)

* PDF 4.2: *a protected application must not trust a client-supplied device ID alone; the device must prove possession of
  its registered private key using mTLS or a nonce-based signed challenge.* A deviceId typed into a form proves nothing.
  The challenge is issued by the platform, single use, short lived, and bound to tenant, user, device and origin.
* AP-2/AP-3: the decision is made by the platform on its own evidence (device registry + posture), never by what the
  browser or agent claims. The agent only supplies a signature.
* The agent's loopback endpoint is reachable by any web page the user visits, so it must never be a general signing
  oracle: it signs only one fixed, domain-separated structure, only for the configured login origin (Origin header
  check + CORS allow-list), and the platform accepts only challenges it issued itself.

## 3. Data

New migration `V11`:

* `oidc_clients.require_trusted_device boolean not null default false`
* `saml_sps.require_trusted_device boolean not null default false`
* `iam_device_login_challenges (id uuid pk, tenant_id, nonce text, expires_at timestamptz, consumed_at timestamptz null, created_at)` (tenant-bound only: the user is not known until the password is checked)
  Index on `expires_at` for cleanup. Challenges live 120 seconds (the push sign-in path can wait up to 60 s before the proof is verified); expired ones are deleted after an hour.

No change to `iam_device_keys`: it already stores `key_algorithm` (`ECDSA_P256` is already accepted by
`DeviceSignatureVerifier`) and `assurance_level`.

## 4. API surface

Internal (service-to-service. NOTE: the public proxy DOES forward the tenant address, so `InternalOnlyFilter` answers 404 to any request carrying a proxy header; same exposure class as `/internal/devices`, see OQ-24/OQ-29):

* `POST /internal/device-challenges` `{tenantId}` -> `{challengeId, nonce, expiresAt}`
* `POST /internal/device-challenges/{id}/verify` `{userId, deviceId, signature, origin}` (userId = the user auth-svc already authenticated) -> `{deviceId, assuranceLevel}` or 401.
  Rules: challenge exists, unexpired, unconsumed (consumed atomically, even when verification fails, so a nonce cannot be
  retried); device belongs to the **same tenant AND the authenticated user**; device is not
  revoked/rejected/decommissioned; signature verifies against the device's active key over the canonical payload
  `iam-device-login-v1\n{tenantId}\n{deviceId}\n{challengeId}\n{nonce}\n{origin}`.

Changed:

* `iam-auth-svc` `LoginRequest` gains optional `deviceProof {challengeId, deviceId, signature, origin}`. Verified through
  tenant-svc; on success the session is issued **with** that deviceId (session-svc already stores `deviceId`); on failure the
  login still succeeds **without** a device (the user is who they say, the device is just not proven) and the reason is audited.
* `GET /api/v1/app-access` additionally receives the session's deviceId. For an app with `require_trusted_device`:
  allow only if `deviceId` is present, the device is `APPROVED`, and posture is not `NON_COMPLIANT`. Otherwise deny with a
  plain reason (see section 6). Posture `UNKNOWN` is allowed (an unreadable probe is not evidence of failure; recorded as OQ-30).
* Admin Console: a "Requires a trusted device" switch on OIDC clients and SAML apps.
* Agent loopback endpoint (in the service process), ports tried in order 47631..47635:
  `GET /v1/identity` -> `{deviceId, tenantId, agentVersion}`; `POST /v1/sign-login` `{challengeId, nonce, origin}` -> `{deviceId, signature}`.
  Both require `Origin` == the origin of `enrollment_login_url`; CORS allows only that origin; replies include
  `Access-Control-Allow-Private-Network: true` for Chrome/Edge Private Network Access preflights. Binds 127.0.0.1 only.
* Login portal: before submitting the password form the page asks the platform for a challenge, asks the agent to sign it,
  and posts the proof with the credentials. No agent running = no proof = sign-in proceeds as today.

## 5. TPM keys (P1-06)

* Windows CNG, provider "Microsoft Platform Crypto Provider", ECDSA P-256, key non-exportable. Software fallback when no
  TPM (existing key). `assurance_level` = `HARDWARE` vs `SOFTWARE`.
* CNG returns ECDSA signatures as raw `r||s` (IEEE P1363); Java's `SHA256withECDSA` expects ASN.1 DER. The backend must use
  `SHA256withECDSAinP1363Format` for `ECDSA_P256` (today's branch would reject a correct signature).
* Enrollment sends the SPKI DER public key and a proof of possession exactly as today; the thumbprint rule is unchanged.
* Migration of the existing software identity to a TPM key is **not automatic**: re-enroll (`--reset-enrollment`).

## 6. Error handling and what the user sees

| Situation | Result |
|---|---|
| Agent not installed or not running | Sign-in works; flagged apps say "This app needs a managed, approved device. Install the endpoint agent." |
| Challenge expired / reused / wrong device owner | Proof rejected, audited; sign-in continues without a device |
| Device suspended / revoked / pending | Flagged apps denied: "Your device is not approved" |
| Device non-compliant | Flagged apps denied: "Your device does not meet the security requirements: <reasons>" |
| Tenant-svc unreachable during the check | Flagged apps denied (fail closed); others unaffected |

## 7. Audit events (minimum schema from ENGINEERING_GUARDRAILS section 3)

`device.login_proof.accepted`, `device.login_proof.rejected` (reason), `app.access.denied_untrusted_device` (appKind, appId,
deviceId, reason). Each carries tenantId, userId, deviceId, correlationId, sourceIp, result.

## 8. Success criteria

1. A valid proof from the owner's approved laptop yields a session with that deviceId; the same proof replayed is rejected.
2. A proof signed by another user's device, an expired or foreign challenge, or a tampered origin is rejected.
3. Suspending the laptop in the console makes a flagged app deny on the next access check, with no app/session changes.
4. A non-flagged app is unaffected by all of the above.
5. A web page on another origin cannot obtain a signature from the agent (Origin check), shown by a test.
6. TPM key: signature from the TPM verifies on the backend (P1363 format) and `assuranceLevel` is `HARDWARE`; no TPM -> software fallback.

## 9. Open questions

* **OQ-29** the `/internal/...` endpoints are unauthenticated service-to-service calls, like `/internal/devices` (OQ-24). Needs the service-to-service mTLS decision before production.
* **OQ-30** posture `UNKNOWN` currently does not block flagged apps; should it, for tenants that want strictness?
* **OQ-31** Chrome/Edge may show a one-time "access devices on your local network" permission prompt for the first loopback call; to be observed in practice and, if needed, pre-approved by browser policy.
* **OQ-32** shared computers: two users on one laptop. The device belongs to the enrolling user; another user's proof is rejected, so they get no device. Is that acceptable?

## 10. Implementation checklist

- [x] S0 spec and decisions (this file)
- [x] S1 tenant-svc: migration V11, challenge issue/verify, app flag, access rule, tests (deployed 2026-11-17)
- [x] S2 auth-svc: accept and verify `deviceProof`, pass deviceId to session (deployed 2026-11-17; a missing, wrong or unverifiable proof never affects the sign-in)
- [x] S3 admin console switch (deployed 2026-11-17; off for every app)
- [x] S4 agent loopback endpoint + tests (Origin/CORS) (built 2026-11-17, 129 agent tests; verified on real Windows; NOT yet in the installed agent: needs a new version)
- [x] S5 login portal challenge flow (deployed 2026-11-17; inert until an app is flagged AND the new agent is installed)
- [x] S6 TPM key provider, P1363 verification, enrollment path (built 2026-11-17, agent 0.2.0; backend verifier deployed; TPM proven on the dev laptop with a per-user key; the machine key and a full TPM enrollment are NOT yet proven)
- [ ] S7 end-to-end run on the real platform
