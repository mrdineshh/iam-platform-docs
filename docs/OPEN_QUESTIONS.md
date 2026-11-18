# Open Questions / Tier-3 Flags Awaiting Human Input

Per ENGINEERING_GUARDRAILS.md §4 (Definition of Done), this file must be
empty before a module is marked done. All Tier-3 items surfaced during the
Module 1 interview were resolved with the product owner and are recorded in
`/docs/DECISIONS.md` (2026-08-03 entries) rather than left pending here.

(No open items at this time. OQ-1 and OQ-2, raised 2026-09-13 during
Service 6, are both resolved -- see `docs/DECISIONS.md`, "Tracing fix and
session-token header move" entry.)


## Open items raised 2026-10-27 (session management, branding, password and lockout policy)

Built because the product owner asked for them; recorded here because each
rests on an assumption a human should confirm.

- **OQ-3 -- Lockout disclosure.** A locked account answers a *wrong* password
  exactly like an unknown user (no lock information leaks), and reports
  `ACCOUNT_LOCKED` only when the *correct* password is supplied. This stops
  lockout state from enabling user enumeration, at the cost that a legitimate
  user who mistypes while locked sees "invalid credentials". Confirm this is
  the wanted trade-off (touches the auth engine, AP-1).
- **OQ-4 -- Lockout default.** FR-3.5 makes lockout configurable but states no
  default. It ships OFF so no existing tenant (including this demo's admin) can
  be locked out by a rollout. Confirm whether new tenants should default to
  on (for example 5 attempts, 15 minutes).
- **OQ-5 -- Sign-in alerts.** Requested ("alert on new sign-in") but no
  BRD requirement covers user notifications, and it needs mail or SMS
  infrastructure. Not built.
- **OQ-6 -- Remaining password policy.** FR-3.2 (history), FR-3.3
  (rotation/expiry) and FR-3.4 (breached-password screening, an external
  HIBP-style dependency not in the approved tech stack) are not built. Only
  FR-3.1 (complexity) and FR-3.5 (lockout) are.
- **OQ-7 -- Logo upload.** Branding takes an https logo URL only. Uploading
  needs object storage (a new dependency) and image validation. Also note the
  login page then loads the logo from the tenant's chosen host; consider a
  Content-Security-Policy `img-src` allowance if CSP is added later.
- **OQ-8 -- Session list/revoke has no explicit FR.** Mapped to FR-11.1 and
  AP-2. Confirm it is in scope for v1 (it is a standard enterprise control).
- **OQ-9 -- `/api/v1/security-settings` is unauthenticated.** Same exposure as
  `/api/v1/evaluate` on the plain-HTTP iam-policy-svc (callers are backends
  holding no admin session). It reveals password rules and the lockout
  threshold. Consider restricting the route at the network edge.

- **OQ-10 -- Move the admin session token out of JavaScript's reach.** The
  console keeps the token in sessionStorage, readable by any script that runs
  in the page. The CSP above makes that much harder to exploit but does not
  remove it. The real fix is an httpOnly cookie, which needs a server-side
  piece (a backend-for-frontend, or cookie sessions in the auth service) plus
  CSRF protection and `credentials` CORS across five services. That changes the
  session transport (Tier 3) so it needs a decision. Related: SESSION_TTL is 8h
  while the login portal's cookie assumes 1h; consider a shorter lifetime for
  admin sessions.

- **OQ-11 -- Apply the OpenBao policy for SCIM tokens.** The tenant service's
  AppRole policy (`cert-issuer`) must allow `secret/data/scim/*` before a SCIM
  connection's token can be stored. `infra/openbao/bootstrap.py` now includes it,
  but it was not applied on the running server: that needs the OpenBao root
  token, which was not authorized for me to use, and re-running bootstrap.py
  rewrites `.env`. Until it is applied, saving a SCIM connection fails at the
  secret write (nothing is saved).
- **OQ-12 -- Direction of SCIM.** Built as outbound provisioning (platform pushes
  to apps), matching the request. FR-2.7 also describes SCIM as a directory
  pushing users into the platform (Entra/AD -> platform, an inbound SCIM server);
  that is not built. Third-party apps must expose a SCIM endpoint to be
  provisioned: Pulse does not (its code has no SCIM routes), so it needs one
  added, or a different mechanism, before it can be deprovisioned from here.
- **OQ-13 -- Who is provisioned to a SCIM app.** Every user of the tenant, not
  only members of groups assigned to the app. Group-scoped provisioning (create
  when a user gains access, remove when they lose it) is a possible refinement.
- **OQ-14 -- Group enforcement is now strict.** A signed-in user without a group,
  or whose group is not assigned to the app, is refused at sign-in (previously
  they could still sign in by opening the app's own link). Apps with no group
  assigned are open to admins only. At the time of this change Pulse had no group
  assigned, so only admins can sign in to Pulse until a group is assigned, and
  users with no group (employee2, employee3, ratnesh) cannot sign in to any app.
- **OQ-15 -- Suspend vs delete in apps.** Suspend sets SCIM `active=false` (kept,
  reversible); delete removes the account. Confirm this matches policy for each
  app.

## Open items raised 2026-11-16 (Endpoint Device Trust / endpoint agent -- recorded late)

The Endpoint Device Trust backend, PEP check, admin page, `/device-enroll` handoff and the Rust agent
(`services/iam-endpoint-agent`) were built 2026-11-09..11-10 from the PDF "IAM Endpoint Device Trust
Technical Specification v1" **without** a SPEC.md interview and without logging these Tier-3 choices
(ENGINEERING_GUARDRAILS.md section 1: crypto/key storage, device-trust logic, uninstall authorization).
That was a process miss. Each item below is something built *provisionally* or *not built*, and needs a
human decision before the agent module can be called done (section 4). None of this was reviewed against
the BRD at the time; BRD Section 5.5 (FR-5.1..5.13) is the source of truth.

- **OQ-16 -- BRD and PDF disagree; which governs?** *Partly resolved 2026-11-16: the product owner directed the team to follow the PDF; the BRD-only items below (OQ-21, OQ-22) remain unbuilt until the owner confirms they should stay dropped or be added back.*  BRD requires: hardware-bound keys (FR-5.2), GPS location
  (FR-5.5/4.7/4.8), remote-authorized uninstall (FR-5.10..5.13), native Chromium sign-in policy with *no*
  extension (FR-5.7, AP-7), network-level block for other browsers (FR-5.8). The PDF omits GPS and uninstall
  entirely and proposes browser *extensions* (PDF section 8). CLAUDE.md says the BRD is the source of truth;
  proposed rule: BRD governs, and PDF items are taken only where they implement a BRD FR.
- **OQ-17 -- Device key is software-only and stored in plaintext.** `agent-core` generates an Ed25519 key and
  persists the private key bytes in `%PROGRAMDATA%\IamEndpointAgent\state.json`. FR-5.2 / NFR-5.1 require a
  TPM/Secure-Enclave-bound, non-extractable key "including by an administrator with root/local admin access".
  The software key is *not acceptable as a default on TPM-capable hardware*; it was built as a stand-in and is
  reported to the backend as assurance level `SOFTWARE`. Also an algorithm/key-storage decision (Tier 3).
- **OQ-18 -- FR-5.3 fingerprint fallback vs PDF.** FR-5.3 says devices without a TPM fall back to a composite
  hardware fingerprint (BIOS serial + disk serial + MAC + CPU ID), flagged lower-assurance. PDF sections 2.3 and
  5.2 say the opposite: never treat serial/MAC/CPU id as proof of identity or make them mandatory (they are
  spoofable and cloneable). Built: no-TPM devices use a software key (proof-of-possession) plus a *correlation-only*
  fingerprint. Needs a decision, and probably a BRD amendment to FR-5.3.
- **OQ-19 -- Nothing binds a device to a login session.** The PEP only checks a device a session *claims*
  (`session.deviceId`), but no code path sets `deviceId` from proof. Needs a design decision on how device
  identity reaches login/PEP: (a) mTLS client certificate from the OS store at the edge, (b) browser extension
  with native messaging signing a challenge, or (c) agent loopback endpoint. FR-5.2 implies an X.509 device
  certificate, which fits (a). Until decided, device trust protects nothing in practice.
- **OQ-20 -- FR-4.9 / AP-4: device rule is not a merged policy.** FR-4.9 says device-based access policy is
  scoped Tenant -> OU/Group -> User with merge-and-hard-cap (FR-4.1/4.2). Built instead: a hardcoded "if the
  session claims a device it must be APPROVED" check in `EnforcementService`. There is no "require a trusted
  device" attribute in `iam-policy-svc`, so a session that simply claims no device is unaffected (a bypass).
- **OQ-21 -- Uninstall authorization (FR-5.10..5.13, AP-8) is not built.** Highest-consequence item: signed,
  time-limited, single-use, device-scoped token; no static password; online only; immutable audit. Tier 3.
- **OQ-22 -- GPS location (FR-5.5, FR-4.7/4.8) is not built** (also absent from the PDF). Needs OS location
  permission handling and a privacy/consent decision.
- **OQ-23 -- The issued device certificate is never used, and was never valid.** *Amended 2026-11-16: it also used the wrong OpenBao API (`issue`, which generates a key server-side, instead of `sign` over the device's own CSR), so every certificate issued was for a discarded key. Issuance is now OFF by default (`iam.device.issue-certificates`) until the CSR/`sign` flow is built.*  OpenBao issues and stores an X.509 certificate, but
  device-authenticated calls (heartbeat, posture, policy) authenticate with a raw Ed25519 signature over
  `"{deviceId}:{timestamp}"` (120s freshness window, so a captured request can be replayed inside the window)
  rather than presenting the certificate (mTLS). Also: certificate renewal (spec section 5.3, appendix A "30 days
  before expiry") is not implemented, and certificate TTL (90 days), CA role name (`endpoint-device`) and the
  5-devices-per-user cap are provisional defaults (PDF D03).
- **OQ-24 -- `/internal/devices/{id}` is unauthenticated and reachable from the internet.** Added for the PEP.
  Its doc comment calls it "mTLS-trusted-caller only", which is **wrong for iam-tenant-svc**: that service is
  plain HTTP and its port 8082 is exposed to 0.0.0.0/0 (DECISIONS 2026-10-29, residual risk). It returns only a
  device's lifecycle status and requires a random device UUID plus tenant UUID (not enumerable), so impact is
  low, but it should require an internal credential or be closed at the network edge. Same class as OQ-9.
- **OQ-25 -- Operator setup not applied; enrollment cannot complete on the live system.** *Amended 2026-11-16: with certificate issuance off, only the transit signing key is needed, and `infra/openbao/device-trust-setup.py` (tested against a real OpenBao) creates it. It is on the VM but has not been run: it needs the root token. PKI setup is no longer required for approval.*  OpenBao needs a
  `pki-device` PKI mount with role `endpoint-device`, a `transit` mount with an `ed25519` key `device-policy`,
  and the tenant service's AppRole policy must allow `pki-device/issue/endpoint-device`,
  `pki-device/revoke` and `transit/sign/device-policy` (same shape as OQ-11). The agent's config also needs that
  transit public key. Additionally `OpenBaoPkiException` is not mapped in `GlobalExceptionHandler`, so a PKI
  outage surfaces as a 500 instead of a 503.
- **OQ-26 -- Posture rules are fixed defaults, and enforcement is off.** (Device-trust logic, Tier 3.) Every tenant gets the
  same required set (BitLocker, antivirus, firewall); PDF section 13.3 expects tenants to configure it, which is not built.
  Confirm: (a) is that the right default required set; (b) should an UNKNOWN (undeterminable) check ever count as a failure;
  (c) when should enforcement (`iam.device.enforce-posture`) be turned on, and per tenant or globally. Until then a
  non-compliant device is flagged in the console but keeps its access.
- **OQ-27 -- OpenBao root token and unseal keys are readable by every login account on the VM (found 2026-11-16).**
  `/opt/iam/Iam_core_Platform/infra/openbao/secrets/init.json` is `-rw-r--r-- root root` inside a directory any account can
  enter; verified by listing it as the unprivileged `nobody` user. It holds the OpenBao root token and the unseal keys, and
  the VM has about ten OS Login accounts (team members). Anyone with a shell there can read it and take over OpenBao (every
  platform secret). Recommended, not yet applied (it changes live infrastructure; confirm that `unseal-on-boot.sh` and
  whoever runs `bootstrap.py` do so as root first): `sudo chmod 700 .../infra/openbao/secrets && sudo chmod 600
  .../infra/openbao/secrets/init.json`, then consider rotating the root token. Better still, move the unseal keys off this
  machine. **Incident, same day:** while preparing a verification run I (the assistant) bundled the whole `infra/openbao`
  folder, which copied `init.json` and the test client certificate/key into world-readable files under `/tmp` on the VM for
  about four minutes. They were securely deleted (`shred`) and the local copy removed. They were already as readable as the
  real file, so no new reader gained access, but if you want certainty, rotate the root token. Cause: archiving a directory
  instead of the two files needed. Prevention: archives for the VM now list files explicitly.

- **OQ-28 -- Where does the allowed-identity-domain list come from?** Today a local `config.json` field. The spec expects it
  from tenant policy. Delivering it through the signed device policy changes the canonical string on the backend and in the
  agent (golden-vector change), so it needs a decision. Also: the agent does not remove the registry values on uninstall, and
  Chrome may treat some registry policies differently on machines that are not domain-joined or enrolled; verify with
  `chrome://policy` on a real machine before relying on it.

## Device-bound sign-in (docs/specs/device-bound-signin-SPEC.md), raised 2026-11-17

- **OQ-29 -- The new `/internal/device-challenges` endpoints are unauthenticated service-to-service calls**, the same exposure class as `/internal/devices` (OQ-24). They are not routed by the public proxy, but nothing inside the network authenticates the caller. Needs the service-to-service mTLS/auth decision before production.
- **OQ-30 -- Posture UNKNOWN does not block "trusted device required" apps** (only NON_COMPLIANT does), because an unreadable probe is not evidence of failure. Should stricter tenants be able to block UNKNOWN too?
- **OQ-31 -- Chrome/Edge may show a one-time "access devices on your local network" prompt** the first time the login page talks to the agent on 127.0.0.1. To be observed in practice; if it is a problem, pre-approve it through the browser policy the agent already writes.
- **OQ-32 -- Shared computers.** A device belongs to the user who enrolled it; another user's sign-in on that laptop gets no device proof (so flagged apps deny them). Acceptable, or should one laptop be allowed to serve several users?
- **OQ-33 -- Anyone can ask the login portal for a device challenge** (the server action behind the login page), but only for a tenant that has at least one app flagged "trusted device required", and expired challenges are deleted after an hour, so the table is bounded by request rate times one hour. There is no rate limit on it. Add one before a tenant with a flagged app is exposed to the open internet at scale.
- **OQ-34 -- A signed-in user with an existing single-sign-on session has no device on it.** *Partly resolved 2026-11-18: the refusal page now names the real reason (no managed device / not approved / failing checks); an old session still needs a fresh sign-in to pick up a device.* Sessions created before the new agent and flagged app existed carry no device, so opening a flagged app shows the generic "no access" page until they sign out and in again; the page does not yet explain why (the denial reason is not passed to the portal).

## Signed agent updates (docs/specs/agent-update-SPEC.md), raised 2026-11-18

- **OQ-35 -- No automatic return to the previous version when an update installs but misbehaves.** Windows Installer rolls a FAILED
  install back by itself, but an update that installs fine and then crashes or cannot reach the platform is not detected: that needs the
  previous MSI kept on the laptop plus a health watchdog that reinstalls it. Not built; the manual way back is to publish a newer,
  fixed version (the agent never accepts an older one).
- **OQ-36 -- The installer itself is not Authenticode-signed.** Our own signature (Ed25519, verified by the agent) protects the update
  channel, but Windows still shows "Unknown publisher" for a manual install, and an administrator-run install has no OS-level check.
  Needs a code-signing certificate (owner's purchase).
- **OQ-37 -- The release is stored in the platform database and sent over the normal API.** Fine for a 4 MB installer and a handful of
  releases; revisit (object storage, a CDN) if releases become frequent or large. The agent does not care where bytes come from.
- **OQ-38 -- One release stream for all tenants.** Releases are not per tenant (`iam_agent_releases` has no tenant column). A tenant that
  wants to stay on an older version has no control today; `PILOT`/`DRAFT` states exist but are not yet targeted at specific devices.
