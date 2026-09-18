# Documentation Brief — Enterprise IAM Platform (Tabular Summary)

Purpose: a quick-reference, table-only summary of what's built vs. what's
left, meant to be handed to a fresh Claude/human session as the seed for
proper documentation. For narrative detail on any row, see
`BUILD_PLAN.md`, `docs/BRD.md`, `docs/DECISIONS.md`, `contracts/*.yaml`.

Two different "scopes" are tracked separately because they're genuinely
different targets:
- **MVP** = `BUILD_PLAN.md`'s deliberately narrowed demo scope (what's
  actually being built right now).
- **Full end product** = `docs/BRD.md`'s complete v1 vision (much bigger;
  MVP is a slice of it).

---

## 1. Backend microservices

| # | Service | Purpose | Status | Done | Remaining |
|---|---|---|---|---|---|
| 0 | `iam-service-kit` + `service-template` | Shared infra library + bootstrap template | ✅ Built & verified | Resilience4j HTTP client, Kafka audit publisher, correlation-ID propagation, shared error shape, OpenBao client, health checks | — |
| 1 | `iam-audit-svc` | Permanent audit log | ✅ Built & verified | Consumes `audit-events`, writes to DB, dead-letters malformed messages | — |
| 2 | `iam-tenant-svc` | Tenant records + OIDC client registry | ✅ Built & verified | Create/get tenant, subdomain lookup, OIDC client register/verify-secret | — |
| 3 | `iam-geo-svc` | IP → country resolution | ✅ Built & verified | DB-IP Lite dataset, private-IP local-dev fixture | Real MaxMind GeoLite2 swap (license key); IPv6 support; region/city granularity |
| 4 | `iam-identity-svc` | User records + password auth | ✅ Built & verified | Create/get user, status patch, Argon2id password verify (enumeration-safe) | SCIM-driven status sync (needs Service 8) |
| 5 | `iam-policy-svc` | Merge-with-hard-cap policy engine (AP-4) | ✅ Built & verified | Country allow/block list, Tenant→OU→User merge, hard-caps | IP-range policy, device-trust policy (FR-4.1) |
| 6 | `iam-session-svc` | Session lifecycle (Valkey) | ✅ Built & verified | Issue (idempotent), validate, terminate, opaque tokens | — |
| 7 | `iam-auth-svc` | **Login orchestrator** (AP-1) | ✅ Built & verified | Password→geo→policy→2FA(TOTP/push)→session, one call, errorCode on denials | Risk-based/adaptive step-up (static "always require 2FA" today, not risk-scored); real server-derived sourceIp for this endpoint |
| 8 | `iam-directory-svc` | Google Workspace OIDC + SCIM | ❌ **Not built** | — | Everything — blocked on product owner creating a Google Cloud OAuth client (human step, not technical) |
| 9 | `iam-device-svc` | 2nd factor: TOTP + push | ✅ Built & verified | Enroll, TOTP verify (hand-rolled RFC 6238, 5-attempt lockout), push send/respond, AES-256-GCM secret storage | "Remember this device" (deliberately absent); real phone push-approve tap (needs Service 12) |
| 10 | `iam-enforcement-svc` (the PEP) | Continuous re-enforcement (AP-2) | ✅ Built & verified | Re-checks session/geo/policy every request, kills session on violation, never fails open | Built in Kotlin not Go (logged deviation, cosmetic) |
| 11 | `iam-oidcprovider-svc` | OIDC Authorization Code provider | ✅ Built & verified | `/authorize` (redirects to portal), `/authorize/complete`, `/token`, `/userinfo`, JWKS, session-tied access tokens | Rotating JWKS (single static key today) |
| 12 | `iam-mobile-android` | Authenticator app | ❌ **Not built** | — | Everything — TOTP display, push approve/deny UI |
| 13 | `iam-login-portal` | Branded login UI (Next.js) | ✅ Built & verified | Real front door, subdomain tenant resolution, combined password+2FA form, real-IP capture, denial messaging | Per-tenant branding (FR-6.1, deferred on purpose); self-service password reset/enrollment (FR-2.14, deferred on purpose) |
| 14 | `iam-admin-console` | Tenant admin UI (React+Vite) | ✅ Built & verified | List/create OIDC clients, view/edit tenant policy, real role-based login (introduced `role` platform-wide) | User management UI (deferred on purpose); cross-tenant super-admin view (deferred on purpose) |

---

## 2. Cross-cutting platform capabilities

| Capability | Status | Done | Remaining |
|---|---|---|---|
| Distributed tracing | ✅ Done | Every service traced via OpenTelemetry → Jaeger, one correlation ID per request chain | Production-grade sampling config (100% is a local-dev-only setting) |
| Audit logging pipeline | ✅ Done | Every security-relevant action → Kafka → permanent DB row, dead-letter on failure | Full compliance program (retention enforcement, access reviews) — not just capture |
| Inter-service resilience | ✅ Done | Circuit breaker + retry + timeout on every inter-service call | — |
| Inter-service authentication | ❌ **Not built** | — | Nothing authenticates service-to-service calls today — any service can call any other's endpoint unauthenticated on the Docker network. Needs mTLS via OpenBao PKI before real deployment |
| Secrets management | ⚠️ Partial | OpenBao stores password pepper, TOTP encryption keys, OIDC signing key | Runs in ephemeral dev mode, no persistence, hardcoded root token — must be hardened before any real deployment |
| RBAC | ⚠️ Minimal | `role` field (ADMIN/USER) now exists platform-wide (Service 14); admin actions are server-side enforced, not just UI-hidden | Granular, custom, OU/group-scoped RBAC (FR-7.x) |
| Cross-origin browser access (CORS) | ✅ Done | Added to `iam-auth-svc`/`iam-tenant-svc`/`iam-policy-svc` for Service 14 — the first browser-direct (non-server-mediated) frontend | Origin list is a single configurable value, not a real per-deployment allowlist policy |
| Cloud deployment | ❌ **Not started** | — | Everything — GCP scoping, real ingress/gateway, hardened secrets, multi-broker Kafka, CloudNativePG |

---

## 3. Remaining for the current MVP (BUILD_PLAN.md's own finish line)

| Item | Blocker | Notes |
|---|---|---|
| Service 8 — `iam-directory-svc` | Needs product owner to create a Google Cloud OAuth client | No technical blocker |
| Service 12 — `iam-mobile-android` | None | Needs a real device/emulator to fully verify push — the only remaining service besides Service 8 |
| Cloud deployment (GCP) | Not yet scoped | Needs OpenBao hardened + real gateway first |

---

## 4. Remaining for the full BRD end product (v1 vision, beyond MVP)

| BRD Area | Status vs. MVP | What's Missing |
|---|---|---|
| FR-1 SSO & App Integration | ⚠️ Partial | Only OIDC tested (1 relying party); no SAML 2.0 support at all |
| FR-2 Directory & Identity | ⚠️ Partial | Only Google Workspace planned (not built); no Entra ID, on-prem AD/ADFS, multi-directory, identity-collision UI |
| FR-3 Auth Policy Engine | ⚠️ Partial | No WebAuthn/passkeys, SMS OTP, Email OTP, password-policy engine (breached-password screening, rotation), or risk-based adaptive step-up — 2FA is flat "always required," not risk-scored |
| FR-4 Contextual Access Control | ⚠️ Partial | Only country-level IP policy; missing IP-range, device-trust, GPS-based restriction, impossible-travel detection, edge/WAF geo-IP restriction of the login URL, and break-glass emergency access (not built at all) |
| FR-5 Endpoint Agent | ❌ Not built | Entire Rust agent: TPM/Secure Enclave device trust, posture checks, GPS geo-restriction, tamper-resistant remote-only uninstall, corporate/personal Google account control |
| FR-6 Branding | ⚠️ Deferred | Per-tenant logo/theme/color — no backend data model or admin UI yet |
| FR-7 Admin/RBAC | ⚠️ Minimal | Two fixed roles only (ADMIN/USER, added Service 14), not granular custom RBAC; Platform Super Admin tier not built |
| FR-8 Mobile Authenticator | ⚠️ Partial | Android only planned (not built); iOS excluded from MVP scope entirely |
| FR-9 Reporting & Analytics | ❌ Not built | No dashboards, no planned service yet |
| FR-10 API & Programmatic Access | ❌ Not built | Service-account/API-key access not implemented |
| FR-11 Audit Logging | ⚠️ Partial | Capture mechanism works end-to-end; retention-policy enforcement and compliance program not done |
| NFR Compliance/Availability | ❌ Not started | SOC 2 / ISO 27001 / GDPR program, 99.99% availability engineering |
| Phase 2/3 (BRD §10) | ❌ Not started, by design | Dedicated single-tenant deploy, on-prem deploy, custom login domains, multi-region — must not be built now, must not be architecturally blocked later |

---

## 5. Known technical debt / deviations (quick reference)

| Item | Type | Notes |
|---|---|---|
| No inter-service auth | Security gap | Any service can call any other unauthenticated (Docker network only, local dev) |
| OpenBao ephemeral, no persistence | Security/reliability gap | Password pepper + TOTP keys wiped on every Docker Desktop restart (has happened repeatedly) |
| Single-broker Kafka, single Postgres host | Reliability gap | Correct topology, not correct redundancy |
| `sourceIp` mostly client-supplied | Security gap | True everywhere except `iam-login-portal`, which reads the real TCP connection |
| Static OIDC signing key | Security gap | Not a real rotating JWKS yet |
| `iam-auth-svc` geo soft-fail gap | Bug, flagged not fixed | Only catches unreachability, not an unexpected 4xx (e.g. a real IPv6 client would 500 the login) |
| Bootstrap role-promotion endpoint unauthenticated | Security gap | `PATCH /users/{id}/role` on `iam-identity-svc` has no auth — necessary to create the first admin, but anyone reaching the service can promote any user |
| Admin console's `sourceIp` is a hardcoded placeholder | Security gap, local-dev-only | A pure browser SPA can't learn its own real IP; sends a fixed private address that only resolves via `iam-geo-svc`'s existing local-dev fixture |
