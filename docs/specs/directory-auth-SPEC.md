# Module 1 SPEC: Directory & Identity Sourcing + Authentication Policy Engine

**Repo:** `iam-core-platform` (Kotlin + Spring Boot)
**BRD coverage:** §5.2 (Directory & Identity Sourcing, FR-2.1–FR-2.14), §5.3
(Authentication Policy Engine, FR-3.1–FR-3.13)
**Governing principles:** AP-1 (unified auth engine), AP-3 (never trust
upstream assertion directly), AP-4 (merge-with-hard-cap — policy *storage*
only; full resolution engine ships with Module 2's PEP), AP-6 (config-driven
attribute mapping), AP-8 (audit everything security-relevant)
**Decisions referenced:** see `/docs/DECISIONS.md`, entries dated 2026-08-03

This module is the foundation every later module depends on: the user/tenant
data model, the directory federation abstraction, the unified factor engine,
and the audit-event contract itself (Guardrails §3 schema is finalized here).

---

## 1. Data Schema

All tables are PostgreSQL, tenant-scoped via `tenant_id` (row-level security
policy enforced at the DB layer — every query must filter by tenant_id; this
is enforced by a Postgres RLS policy, not just application-layer discipline,
as defense in depth for tenant isolation). All primary keys are UUIDv7
(time-ordered, avoids index fragmentation vs UUIDv4).

### 1.1 `tenants`
| Field | Type | Constraints | Configurable? |
|---|---|---|---|
| `id` | UUID | PK | system |
| `name` | text | not null | tenant admin |
| `subdomain` | text | unique, not null, lowercase, DNS-safe | tenant admin (once, at onboarding) |
| `status` | enum(`active`,`suspended`,`deprovisioning`) | not null, default `active` | system |
| `created_at` | timestamptz | not null | system |
| `password_pepper_key_ref` | text | not null | system — OpenBao Transit key reference, never the raw pepper |

### 1.2 `directory_sources`
One row per connected upstream directory (FR-2.9 — multiple per tenant).

| Field | Type | Constraints | Configurable? |
|---|---|---|---|
| `id` | UUID | PK | system |
| `tenant_id` | UUID | FK tenants, not null | system |
| `source_type` | enum(`entra_id`,`adfs_saml`,`generic_saml`,`generic_oidc`,`onprem_ad_ldap`) | not null | tenant admin |
| `display_name` | text | not null | tenant admin |
| `provisioning_mode` | enum(`jit_only`,`scim`,`jit_and_scim`) | not null, default `jit_only` | tenant admin (FR-2.6–FR-2.8) |
| `metadata` | jsonb | not null | tenant admin — protocol-specific config (SAML metadata URL/cert, OIDC discovery URL/client creds ref, LDAP connector binding ref for `onprem_ad_ldap`) |
| `attribute_mapping_id` | UUID | FK `attribute_mappings`, not null | tenant admin |
| `collision_match_attribute` | enum(`email`,`employee_id`) | not null, default `email` | tenant admin (Decision 2026-08-03) |
| `enabled` | boolean | not null, default true | tenant admin |
| `created_at`, `updated_at` | timestamptz | not null | system |

`metadata` secrets (client secrets, SAML signing certs) are never stored
inline — the jsonb holds an OpenBao path reference; actual secret material
lives in OpenBao only (Guardrails §4 "no hardcoded secrets" applies equally
to "no secrets in the app DB" for this field).

### 1.3 `attribute_mappings` (AP-6)
Versioned, schema-driven — never hardcoded per integration.

| Field | Type | Constraints |
|---|---|---|
| `id` | UUID | PK |
| `tenant_id` | UUID | FK tenants |
| `version` | int | not null, monotonic per tenant |
| `mapping_rules` | jsonb | not null — array of `{source_claim, platform_attribute, transform?}` |
| `is_active` | boolean | not null |
| `created_at` | timestamptz | not null |

Changing a mapping creates a new version row rather than mutating in place
(auditability of what mapping was active when a given user record was synced).

### 1.4 `users`
| Field | Type | Constraints | Configurable? |
|---|---|---|---|
| `id` | UUID | PK | system |
| `tenant_id` | UUID | FK tenants, not null | system |
| `primary_directory_source_id` | UUID | FK directory_sources, nullable (null = local/platform-native account) | system |
| `email` | citext | not null | synced or admin-set |
| `employee_id` | text | nullable | synced |
| `display_name` | text | not null | synced |
| `status` | enum(`active`,`disabled`,`pending_collision_resolution`) | not null, default `active` | system/admin |
| `password_hash` | text | nullable (null if passwordless-only or federated-only account) | system |
| `password_updated_at` | timestamptz | nullable | system |
| `failed_login_count` | int | not null, default 0 | system |
| `lockout_state` | enum(`none`,`temporary`,`permanent`) | not null, default `none` | system |
| `lockout_until` | timestamptz | nullable | system |
| `created_at`, `updated_at` | timestamptz | not null | system |

Unique constraint: `(tenant_id, email)` — enforces per-tenant uniqueness;
cross-directory collision on the *same* tenant is what FR-2.10 detects
(see §1.6 below), this constraint is what makes a collision detectable in
the first place rather than silently creating two rows.

### 1.5 `user_directory_links`
Supports FR-2.9 (multi-directory per tenant) and FR-2.10 (collision
detection) — a user can, post-resolution, be linked to more than one source.

| Field | Type | Constraints |
|---|---|---|
| `id` | UUID | PK |
| `user_id` | UUID | FK users |
| `directory_source_id` | UUID | FK directory_sources |
| `external_id` | text | not null — the source system's own ID (objectGUID, sub claim, etc.) |
| `last_synced_at` | timestamptz | nullable |
| `raw_attributes` | jsonb | not null — last-synced raw claims, pre-mapping, for debugging/audit |

Unique constraint: `(directory_source_id, external_id)`.

### 1.6 `identity_collisions`
FR-2.10 — silent auto-merge is prohibited; this table is the manual-resolution
queue.

| Field | Type | Constraints |
|---|---|---|
| `id` | UUID | PK |
| `tenant_id` | UUID | FK tenants |
| `matched_attribute_value` | text | not null (the colliding email/employeeID) |
| `candidate_user_directory_link_ids` | UUID[] | not null, length >= 2 |
| `status` | enum(`pending`,`resolved_merged`,`resolved_kept_separate`) | not null, default `pending` |
| `resolved_by_admin_id` | UUID | nullable |
| `resolved_at` | timestamptz | nullable |
| `created_at` | timestamptz | not null |

### 1.7 `auth_factors`
Unified factor storage (AP-1 — one engine, one table shape for all factor
types, not a table per factor type).

| Field | Type | Constraints |
|---|---|---|
| `id` | UUID | PK |
| `user_id` | UUID | FK users |
| `factor_type` | enum(`password`,`fido2`,`totp`,`sms_otp`,`email_otp`,`push`) | not null |
| `secret_ref` | text | nullable — for `totp`: OpenBao-encrypted envelope reference (Decision 2026-08-03). For `fido2`: column-level-encrypted credential ID + public key + counter, stored directly (public key material, encrypted at rest for integrity not secrecy). For `password`: null, hash lives on `users.password_hash`. |
| `phone_number` / `email_address` | text | nullable — required for `sms_otp` / `email_otp` respectively |
| `is_primary` | boolean | not null, default false |
| `created_at`, `last_used_at` | timestamptz | |
| `revoked_at` | timestamptz | nullable |

### 1.8 `password_policies`, `factor_policies` (Tenant/OU/User-scoped)
Per AP-4, these are stored at three levels; the actual merge-resolution logic
is Module 2 scope (it lives with the PEP/policy-resolution engine), but the
**storage model** is finalized here since Module 2 depends on it.

| Field | Type | Constraints |
|---|---|---|
| `id` | UUID | PK |
| `tenant_id` | UUID | FK tenants |
| `scope_level` | enum(`tenant`,`ou`,`user`) | not null |
| `scope_ref_id` | UUID | nullable — OU id or user id; null when scope_level=tenant |
| `policy_type` | enum(`password`,`factor`,`lockout`) | not null |
| `policy_body` | jsonb | not null — shape defined per policy_type (see §2.6) |
| `is_hard_cap` | boolean | not null, default false — AP-4 |
| `created_by_admin_id` | UUID | not null |
| `created_at`, `updated_at` | timestamptz | |

### 1.9 `breached_password_check_log`
Supports the degraded-mode decision (async re-check queue).

| Field | Type | Constraints |
|---|---|---|
| `id` | UUID | PK |
| `user_id` | UUID | FK users |
| `password_hash_prefix` | text | not null — k-anonymity prefix only, never the password itself |
| `checked_at` | timestamptz | nullable — null while pending |
| `result` | enum(`pending`,`clean`,`breached`,`check_failed`) | not null, default `pending` |
| `created_at` | timestamptz | not null |

---

## 2. API Surface

Base path: `/api/v1`. All endpoints require tenant context (subdomain or
`X-Tenant-Id` for API-key callers) and RBAC permission check (RBAC itself is
Module 4, but every endpoint below declares its required permission now so
Module 4 has a stable contract to implement against).

### 2.1 Directory Source Management
| Method | Path | Purpose | Permission | FR |
|---|---|---|---|---|
| POST | `/directory-sources` | Create a directory source | `tenant.directory.write` | FR-2.1–FR-2.4 |
| GET | `/directory-sources` | List directory sources for tenant | `tenant.directory.read` | FR-2.9 |
| GET | `/directory-sources/{id}` | Get one | `tenant.directory.read` | — |
| PATCH | `/directory-sources/{id}` | Update config/mapping/provisioning mode | `tenant.directory.write` | FR-2.6–FR-2.8 |
| DELETE | `/directory-sources/{id}` | Disable/remove a source | `tenant.directory.write` | — |
| POST | `/directory-sources/{id}/test-connection` | Validate connectivity without persisting | `tenant.directory.write` | operational necessity, not directly FR-numbered |

**Request schema — POST `/directory-sources`:**
```json
{
  "source_type": "entra_id | adfs_saml | generic_saml | generic_oidc | onprem_ad_ldap",
  "display_name": "string",
  "provisioning_mode": "jit_only | scim | jit_and_scim",
  "metadata": { "...protocol-specific, secrets as openbao path refs only..." },
  "attribute_mapping": [
    { "source_claim": "string", "platform_attribute": "string", "transform": "string|null" }
  ],
  "collision_match_attribute": "email | employee_id"
}
```
**Response:** the created `directory_sources` row (secrets never echoed back —
`metadata` in responses shows OpenBao path refs only, never resolved values).

### 2.2 SCIM 2.0 Endpoint (FR-2.7)
Standard SCIM 2.0 surface, RFC 7643/7644 compliant, scoped under
`/scim/v2/{directory_source_id}/`:
| Method | Path | Purpose |
|---|---|---|
| POST | `/scim/v2/{id}/Users` | Create user |
| GET | `/scim/v2/{id}/Users/{scim_id}` | Read user |
| PUT/PATCH | `/scim/v2/{id}/Users/{scim_id}` | Update user |
| DELETE | `/scim/v2/{id}/Users/{scim_id}` | Deprovision (maps to `users.status = disabled`, never a hard delete — audit trail preservation) |
| GET | `/scim/v2/{id}/Users?filter=...` | Search (required for SCIM compliance) |

Auth: bearer token, a SCIM-specific credential type issued per directory
source (distinct from tenant admin session auth — this is the identity
source's own credential, scoped to SCIM write only).

### 2.3 Identity Collision Resolution (FR-2.10)
| Method | Path | Purpose | Permission |
|---|---|---|---|
| GET | `/identity-collisions?status=pending` | List unresolved collisions | `tenant.directory.read` |
| POST | `/identity-collisions/{id}/resolve` | Resolve — body: `{"action": "merge \| keep_separate", "primary_user_directory_link_id": "uuid (if merge)"}` | `tenant.directory.write` |

### 2.4 Authentication (FR-3.x)
| Method | Path | Purpose | FR |
|---|---|---|---|
| POST | `/auth/login` | Step 1: identify + primary factor (password or passwordless trigger) | FR-3.6, FR-3.10 |
| POST | `/auth/login/factor-challenge` | Step 2 (if policy requires step-up/MFA): submit second factor | FR-3.11, FR-3.12 |
| POST | `/auth/factors` | Enroll a new factor (self-service) | FR-2.14 |
| DELETE | `/auth/factors/{id}` | Revoke a factor | FR-2.14 |
| POST | `/auth/password/change` | Self-service password change (triggers breach check, history check) | FR-3.1–FR-3.4 |
| POST | `/auth/password/reset-request` / `/auth/password/reset-confirm` | Self-service reset flow | FR-2.14 |

**`POST /auth/login` — response is intentionally risk-score-driven, not
binary:**
```json
{
  "outcome": "success | step_up_required | denied",
  "session_token": "opaque-token (only if outcome=success)",
  "risk_score": 0.0,
  "required_factor_types": ["fido2", "totp"],
  "challenge_id": "uuid (if step_up_required)"
}
```
This response shape is what makes AP-1 real at the API level: there is one
login endpoint, and "passwordless," "password+MFA," and "adaptive step-up"
are all just different values flowing through the same response contract
based on policy + risk score — never a separate endpoint per auth mode.

Note: full risk-signal computation (impossible travel, IP reputation,
device recognition) depends on contextual signals that are Module 2's
domain (PEP/contextual access control owns IP/geo/device signal collection
per FR-3.13's "avoid duplicate signal-collection logic"). This module
implements the risk-scoring *consumer* interface and a minimal viable
signal set (new-device detection via a device-recognition cookie, and
basic velocity/impossible-travel using login history already in this
module's own data) so login works standalone; Module 2 will feed richer
signals into the same interface without changing this contract.

### 2.5 Password Policy Configuration
| Method | Path | Purpose | FR |
|---|---|---|---|
| PUT | `/policies/password?scope=tenant\|ou\|user&scope_ref_id=...` | Set password policy at a scope | FR-3.1–FR-3.5 |
| GET | `/policies/password?scope=...` | Read effective policy config at a scope (raw, not yet merged — merge resolution is Module 2) | — |

**`policy_body` shape for `policy_type=password`:**
```json
{
  "min_length": 12,
  "require_char_classes": ["upper","lower","digit","special"],
  "history_count": 5,
  "rotation_days": null,
  "breach_screening_enabled": true,
  "breach_screening_fail_mode": "fail_available | fail_closed",
  "lockout_threshold": 5,
  "lockout_duration_minutes": 15,
  "permanent_lock_after_threshold": 10
}
```

### 2.6 Attribute Mapping
| Method | Path | Purpose |
|---|---|---|
| GET | `/directory-sources/{id}/attribute-mapping` | Get active mapping version |
| PUT | `/directory-sources/{id}/attribute-mapping` | Create new mapping version (never mutates existing — see §1.3) |
| GET | `/directory-sources/{id}/attribute-mapping/versions` | History |

---

## 3. Audit Events Emitted

All events use the Guardrails §3 base schema. Module-specific `action` values
and extra fields below.

| `action` | Trigger | `result` values | Extra fields |
|---|---|---|---|
| `directory_source.created` / `.updated` / `.disabled` | Admin CRUD on directory source | `success` | `source_type` |
| `scim.user_provisioned` / `.deprovisioned` | SCIM lifecycle event | `success`,`failure` | `directory_source_id`, `scim_external_id` |
| `identity_collision.detected` | FR-2.10 trigger | `denied` (blocks silent merge) | `matched_attribute`, `candidate_count` |
| `identity_collision.resolved` | Admin resolves | `success` | `resolution_action` (`merge`/`keep_separate`) |
| `auth.login_attempt` | Every login attempt, success or fail | `success`,`failure`,`denied` | `factor_types_used`, `risk_score` |
| `auth.step_up_triggered` | Adaptive MFA invoked | `success` (informational, not itself a failure) | `risk_score`, `trigger_reason` (e.g. `new_device`, `impossible_travel`) |
| `auth.factor_enrolled` / `.factor_revoked` | Self-service factor management | `success`,`failure` | `factor_type` |
| `auth.password_changed` | FR-3.1 | `success`,`failure` | — |
| `auth.password_breach_check_degraded` | Breach API circuit breaker open, fail-available path taken | `success` (proceeded), logged regardless | `password_hash_prefix` (k-anon prefix only) |
| `auth.account_locked` | Lockout threshold hit | `denied` | `lockout_type` (`temporary`/`permanent`), `failed_attempt_count` |
| `auth.account_unlocked` | Admin/Super Admin clears lockout | `success` | `unlocked_by_role` (`tenant_admin`/`platform_super_admin`) — the latter always emitted at break-glass-equivalent severity per Decision 2026-08-03 |
| `policy.password_policy_updated` / `.factor_policy_updated` | Admin changes policy at any scope | `success` | `scope_level`, `scope_ref_id`, `is_hard_cap` |

`policy_scope_applied` (base schema field) is populated wherever an action's
outcome depended on policy resolution (e.g. `auth.login_attempt`,
`auth.account_locked`) — even though full multi-level resolution ships in
Module 2, this module's lockout/password-policy checks already resolve
against whichever scope levels exist today, so the field is populated from
day one rather than retrofitted.

---

## 4. Error Handling Specifics (deltas from Guardrails §2 baseline)

- **Directory source connectivity** (Entra/ADFS/generic SAML/OIDC/LDAP
  connector): circuit breaker per §2 baseline (5 consecutive failures, 30s
  half-open). While open, JIT login attempts against that source fail with
  `outcome: denied` and a clear `reason` — **not** a silent fallback to any
  cached/stale assertion.
- **SCIM sync failures:** retried per baseline (exponential backoff, capped
  at 5, idempotency key = SCIM external_id + operation type so a retried
  create/update/delete can't double-apply). Exhausted retries → dead-letter
  Kafka topic `scim-sync-dlq`, with a Prometheus counter, per baseline —
  **not** silently dropped, since a missed deprovisioning event is a
  security-relevant gap even though the failure itself is operational.
- **Breached-password API:** circuit breaker per baseline. Open-circuit
  behavior is the fail-available / fail-closed split per Decision
  2026-08-03 (§2.5 `breach_screening_fail_mode`), not a blanket rule —
  this is the one deliberate, documented exception to "graceful
  degradation = safer default," because "safer" here is genuinely
  tenant-dependent (compliance posture vs. availability), unlike the
  IP-geolocation case in Guardrails §2 where "treat unresolvable as
  higher-risk" is unambiguous.
- **Password hashing (Argon2id) latency:** must be tuned so p99 verification
  time stays under 250ms even at the OWASP-baseline cost parameters, to
  avoid the login endpoint becoming the resilience bottleneck under load —
  measured explicitly in the load test (§5, Success Criteria).

---

## 5. Success Criteria (beyond generic Definition of Done)

- A single tenant can connect **two simultaneous directory sources** (e.g.
  Entra ID + a generic OIDC IdP) and users from both resolve into the same
  `users` table without collision, per FR-2.9.
- Deliberately creating a collision (two directory sources both claiming the
  same email) produces exactly one `identity_collisions` row and **zero**
  auto-merged user records — this is the single most important negative
  test in this module (FR-2.10 is a "must never silently merge"
  requirement).
- `POST /auth/login` demonstrably returns `step_up_required` for a
  configured-adaptive-policy tenant when the minimal viable risk signal set
  detects a new device, and `success` directly for a recognized device
  under an otherwise-identical policy — proving AP-1 (one endpoint, policy-
  driven outcome) rather than two code paths.
- Killing the (mocked) breached-password API mid-test and re-attempting a
  password change exercises both configured `breach_screening_fail_mode`
  values and confirms the correct one occurs, with the
  `auth.password_breach_check_degraded` audit event present when
  fail-available is taken.
- Account lockout: reaching `lockout_threshold` produces `temporary` lock
  with correct `lockout_until`; reaching `permanent_lock_after_threshold`
  requires explicit unlock action and cannot self-clear on timeout.
- SCIM deprovisioning (`DELETE /scim/v2/.../Users/{id}`) results in
  `users.status = disabled`, never a hard row delete — verified by test,
  since audit/reporting modules downstream depend on the row surviving.
- Load/latency check on `/auth/login` (Argon2id-inclusive path) at
  configured cost parameters meets the p99 target above under a realistic
  concurrent-login load profile.

---

## 6. Open Questions / Tier-3 Flags

All Tier-3 items surfaced during this interview were resolved with the
product owner and are recorded in `/docs/DECISIONS.md` (2026-08-03 entries).
Per Guardrails §4 Definition of Done, this section must be empty before the
module is marked done — it is empty as of this SPEC's completion.

One related item is logged for awareness, not as a blocker to *this*
module: the `iam-adfs-ldap-connector` repo (FR-2.4) is now referenced in
`/CLAUDE.md`'s repo list but its own build has not been scoped/interviewed —
that happens as its own module per the decision logged 2026-08-03. This
module only needs its outbound-connector *protocol contract* (mTLS gRPC,
connector-initiated) to be stable, which is reflected in
`directory_sources.metadata` for `source_type=onprem_ad_ldap` above.
