# Decision Log

Tier-2 decisions (implemented, recorded here per ENGINEERING_GUARDRAILS.md §1).
Format: `[module] [date] — decision — rationale — FR/AP reference`.

Note: several entries below are crypto/key-storage/scope decisions that are
Tier-3 by the letter of the Guardrails (§1, Tier 3 bullet 2 and 4). They are
recorded here rather than left silent because they were explicitly surfaced to
and confirmed by the human product owner during the Module 1 interview
(2026-08-03), satisfying the "stop and flag" requirement. They are logged here
rather than OPEN_QUESTIONS.md because they are now resolved, not pending.

---

- **[iam-core-platform] 2026-08-03** — Password hashing: Argon2id
  (m=19456 KiB, t=2, p=1, OWASP baseline) with a per-tenant pepper held in
  OpenBao Transit in addition to the standard per-user salt — a full DB
  export alone is insufficient for offline cracking. — FR-3.1–FR-3.5,
  confirmed with product owner.

- **[iam-core-platform] 2026-08-03** — Internal platform session tokens
  (admin console, login portal, PEP-gated app sessions) are opaque,
  server-side-referenced tokens backed by Valkey — not self-contained JWTs.
  Required so AP-2's "kill mid-flight, in real time" guarantee is a direct
  Valkey lookup, not a JWT-revocation workaround. This is distinct from
  outbound SAML assertions / OIDC id_tokens issued to downstream SPs, which
  remain signed per-spec (RS256 minimum, EdDSA optional), keys held in
  OpenBao PKI, served via a rotating JWKS endpoint. — AP-2, AP-3,
  FR-4.4, confirmed with product owner.

- **[iam-core-platform] 2026-08-03** — TOTP shared secrets: AES-256-GCM
  envelope encryption, per-tenant DEK wrapped by OpenBao (decryptable by
  design, since verification requires deriving the current code — cannot be
  hashed like a password). FIDO2/WebAuthn credential IDs/counters: standard
  column-level encryption (public keys are not secret by design, but
  integrity of the stored credential record matters). — FR-3.6, confirmed
  with product owner.

- **[iam-core-platform] 2026-08-03** — Identity collision detection (FR-2.10)
  default matching attribute: email. employeeID available as a per-tenant
  override for organizations where email addresses are recycled/reassigned.
  Documented as a known edge case, not a design flaw. — FR-2.10, confirmed
  with product owner.

- **[iam-core-platform] 2026-08-03** — Breached-password API (FR-3.4)
  degraded-mode behavior when the circuit breaker is open: default to
  fail-available — allow the password change/signup to proceed, log a
  `password.breach_check_degraded` audit event, and queue an async
  re-check against the same password hash-prefix once the dependency
  recovers. Tenant-configurable override to fail-closed (block until the
  check succeeds) for tenants with stricter compliance postures. Default
  chosen over fail-closed because a third-party outage should not become a
  self-inflicted denial-of-service on the platform's own signup/reset flow.
  — FR-3.4, Guardrails §2 (graceful degradation), confirmed with product
  owner.

- **[iam-core-platform] 2026-08-03** — Permanent account lockout unlock
  authority (FR-3.5): Tenant Admin is the normal unlock path. Platform
  Super Admin retains a break-glass-tier override (for the case where a
  tenant has locked out its only admin), logged at the same audit severity
  as FR-4.11 break-glass access. This override is specified now (Module 1)
  but its actual invocation flow is implemented alongside the break-glass
  mechanism in Module 2, since it shares that mechanism's audit/alerting
  path. — FR-3.5, FR-4.11, confirmed with product owner.

- **[iam-core-platform] 2026-08-03** — FR-2.4 (on-prem AD-without-ADFS
  connector) scope split: the outbound protocol contract (mTLS-authenticated
  gRPC, connector-initiated, no inbound port required on customer network) is
  specified now as part of this module's directory-source abstraction, so the
  core data model is correct from day one. The connector itself
  (`iam-adfs-ldap-connector`, a customer-premises deployable, likely Go — see
  OPEN_QUESTIONS.md for repo-list gap) is deferred to its own dedicated
  build module, given its distinct deployment target and security review
  surface (direct customer AD access). — FR-2.4, confirmed with product
  owner.
