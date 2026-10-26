# Project: Enterprise IAM Platform (v1 — Multi-Tenant SaaS)

## Overview

A multi-tenant SaaS Identity and Access Management platform: SSO (SAML 2.0/OIDC) to
any integrated SaaS/web app, federation with customer directories (Entra ID, on-prem
AD, ADFS), a unified adaptive authentication engine (password, passwordless, MFA,
risk-based step-up), contextual access control (IP/geo/device, enforced continuously
not just at login), and a cross-platform endpoint agent for device trust and
tamper-resistant enforcement.

**Full requirements:** `/docs/BRD.md` — every requirement is numbered (`FR-x.x`,
`NFR-x.x`). Treat these numbers as the source of truth. If an implementation
decision isn't covered there, ask rather than assume — do not silently narrow or
expand scope.

**Operating rules for autonomous work:** `/docs/ENGINEERING_GUARDRAILS.md` —
defines what you can decide alone vs. must flag before proceeding, the standard
error-handling pattern, the minimum audit-event schema, and the Definition of Done
every module must meet. Read this before starting any module.

## Non-Negotiable Architecture Principles (see BRD Section 4 for full rationale)

Do not "simplify away" any of these, even if it looks like dead weight for an MVP:

- **AP-1 — One auth engine, not five.** Password / passwordless / MFA / adaptive
  step-up are policy configurations of a single factor engine + policy engine.
  Never build a separate code path for "passwordless login."
- **AP-2 — PEP, not login-only checks.** IP/geo/device policy is enforced
  continuously through a Policy Enforcement Point on every request, not just at
  login. Session must be killable mid-flight on policy violation.
- **AP-3 — Never trust an upstream IdP assertion directly.** AD/Entra/ADFS only
  prove identity. The platform's own policy engine always evaluates before a
  session is issued — no bypass path where an upstream assertion alone creates a
  session.
- **AP-4 — Policy resolution = merge, not override, with hard-caps.** Tenant → OU/
  Group → User policies merge (more specific wins per-attribute); tenant admins can
  mark specific policies as non-overridable hard-caps.
- **AP-5 — Deployment-agnostic core.** Containerized, config-driven multi-tenancy,
  no hard cloud-vendor lock-in — v1 ships multi-tenant SaaS only, but the core must
  not preclude dedicated-tenant or on-prem later.
- **AP-6 — Attribute mapping is a config/schema-driven layer**, never hardcoded per
  integration.
- **AP-7 — The agent is a policy/posture/network-control agent, NOT a TLS-
  inspecting proxy.** Do not implement general HTTPS decryption for any feature,
  including the Google personal-account restriction. Use native Chromium enterprise
  policy for Chrome/Edge; targeted domain block/redirect for other browsers.
- **AP-8 — Every break-glass access and every agent-uninstall authorization is
  immutably audited** (who, what, which device/tenant, when).

## Explicitly Excluded — Do Not Build

- Magic links, voice-call OTP, grid-card auth factors
- A general-purpose TLS-inspecting/decrypting proxy
- Static/local agent-uninstall passwords, or any offline uninstall path (uninstall
  requires an online, single-use, device-scoped, remotely-issued token — no
  exceptions)
- Custom customer-owned login domains (v1 is subdomain-only: `tenant.platform.com`)
- A public, self-registerable developer API (API access is service-account/API-key
  only, issued by tenant admins for their own use)
- Dedicated single-tenant or on-prem deployment (Phase 2/3 — see BRD Section 9;
  don't build now, don't architecturally block later)

## Build Order

Modules have real dependencies — build in this sequence, one module per session,
using the interview-then-spec pattern below:

1. Directory & Identity Sourcing + Authentication Policy Engine (foundation)
2. Contextual Access Control + Policy Enforcement Point (gateway layer)
3. SSO / Identity Broker (SAML/OIDC federation)
4. Admin / RBAC + Branding
5. Endpoint Agent — separate repo/codebase, different language & deployment target
   than the backend
6. Mobile Authenticator app
7. Reporting & API layer

## Repository & Module Structure

**Monorepo (changed 2026-10-26 — see `docs/DECISIONS.md`).** The original plan
here was a polyrepo (independent build/CI/deploy per service, matching AP-5's
on-prem-portability reasoning). That tradeoff mainly pays off with multiple
teams working independently; with a single developer building every service,
the daily cost of a polyrepo (one feature routinely touches 3-5 services at
once — e.g. the SAML IdP build, the group-based app-access feature — each
needing its own clone/commit/PR) outweighed the isolation benefit. Switched to
one repo, all service code under `services/`. **This did not change how
anything deploys**: each service still builds its own independent Docker
image from its own folder (`docker-compose.yml`'s build `context` points at
`./services`, each Dockerfile `COPY`s only its own subfolder) — a monorepo is
a source-control decision, not a deployment one. AP-5 (on-prem portability,
a service being extracted to ship independently later) is unaffected: nothing
stops pulling a folder back out into its own repo when that's actually needed.

```
Iam_core_Platform/                (this repo — monorepo root)
├── CLAUDE.md
├── docs/
│   ├── BRD.md
│   ├── ENGINEERING_GUARDRAILS.md
│   ├── DECISIONS.md             (Tier-2 decision log)
│   ├── OPEN_QUESTIONS.md        (Tier-3 flags awaiting human input)
│   ├── INTERNALS.md             (deep technical walkthrough, every service)
│   └── specs/                   (one <module>-SPEC.md per module, see below)
├── infra/                       (Helm charts, OpenTofu configs — portable, no app code)
├── docker-compose.yml           (local/demo orchestration — build context: ./services)
└── services/
    ├── iam-tenant-svc/          (Kotlin + Spring Boot — tenants, OIDC clients,
    │                              SAML SPs, groups, admin proxy endpoints)
    ├── iam-identity-svc/        (Kotlin + Spring Boot — users, passwords, groups)
    ├── iam-auth-svc/            (Kotlin + Spring Boot — the one login orchestrator, AP-1)
    ├── iam-policy-svc/          (Kotlin + Spring Boot — merge-with-hard-cap policy engine)
    ├── iam-session-svc/         (Kotlin + Spring Boot — Valkey-backed sessions)
    ├── iam-device-svc/          (Kotlin + Spring Boot — TOTP/push second factor)
    ├── iam-geo-svc/             (Kotlin + Spring Boot — offline IP → country lookup)
    ├── iam-enforcement-svc/     (Kotlin + Spring Boot — the PEP: continuous
    │                              enforcement + reverse-proxy gateway for
    │                              connected apps, AP-2)
    ├── iam-oidcprovider-svc/    (Kotlin + Spring Boot — OIDC + SAML 2.0 IdP:
    │                              both protocols other apps use for SSO)
    ├── iam-audit-svc/           (Kotlin + Spring Boot — Kafka consumer, audit_db)
    ├── iam-service-kit/         (Kotlin — shared technical plumbing library only,
    │                              no domain concepts, see Section 2.11 INTERNALS.md)
    ├── iam-admin-console/       (React + Vite — tenant admin SPA)
    ├── iam-login-portal/        (Next.js — public login/self-service, SSR)
    └── service-template/        (scaffold for the next new service)
```

**Not yet built** (future phases — do not build now, see BRD Section 9):
`iam-adfs-ldap-connector` (Go, on-prem AD connector, FR-2.4), `iam-endpoint-agent`
(Rust), `iam-mobile-ios` (Swift), `iam-mobile-android` (Kotlin). When these
start, they land in `services/` the same way — the monorepo decision applies
to the whole project, not just what exists today.

Each service's own `CLAUDE.md` (inheriting the same AP-1–AP-8 principles,
scoped to what's relevant for that service) lives inside its own
`services/<name>/` folder once that module's build begins.

## Workflow For Each Module

1. Interview: "Read `/docs/BRD.md` section [X], the relevant AP-x principles,
   and `/docs/ENGINEERING_GUARDRAILS.md` Section 5. Interview me on anything
   underspecified for implementation, then write the result to
   `/docs/specs/<module>-SPEC.md`, covering every item in Guardrails Section 5
   (data schema, API surface, audit events, error handling specifics, success
   criteria, open questions)."
2. Any Tier-3 decision surfaced during the interview goes into
   `/docs/OPEN_QUESTIONS.md` and must be resolved before implementation starts,
   not deferred to "figure out while coding."
3. Start a **fresh session** referencing only that module's SPEC.md to implement
   — don't carry over exploration context from the interview session.
4. No module is marked done until it satisfies
   `/docs/ENGINEERING_GUARDRAILS.md` Section 4 (Definition of Done) in full.

## Tech Stack

This is a polyglot architecture by deliberate choice — each component uses the best
technical fit for its workload, not a single shared stack. Do not consolidate onto
one language/framework "for simplicity"; do not substitute a managed cloud service
for any of the self-hosted choices below without flagging it first (see AP-5 —
everything here is chosen to be portable to on-prem later).

| Layer | Choice |
|---|---|
| Core platform (directory sync, auth policy engine, admin APIs, RBAC, SCIM) | Kotlin + Spring Boot |
| PEP / Gateway (continuous request-level policy enforcement) | Go |
| Endpoint Agent (Windows/macOS/Linux, TPM/Secure Enclave access, elevated privilege) | Rust |
| Mobile Authenticator app | Swift (iOS) + Kotlin (Android) — native, not React Native |
| Admin Console (tenant admin: policy config, RBAC, dashboards) | React + Vite, SPA |
| Login / Self-Service Portal (public-facing, branded per tenant) | Next.js, SSR |
| Primary datastore (tenants, users, policies, RBAC) | PostgreSQL — self-hosted on GKE via CloudNativePG operator (NOT Cloud SQL) |
| Cache / session / PEP policy lookups | **Valkey** — self-hosted on GKE (NOT Redis — see Licensing note below) |
| Audit log store (Section 5.11 — full user/admin/security event logging) | OpenSearch — self-hosted on GKE |
| Event streaming (SCIM sync, webhook delivery, audit ingestion, posture signals) | Kafka — via Strimzi operator on GKE |
| PKI (device certs, FR-5.2) + general secrets management | **OpenBao** — self-hosted (NOT HashiCorp Vault — see Licensing note below) |
| Container orchestration | Plain Kubernetes + Helm charts — GKE now, portable to on-prem k3s/RKE2 later. Avoid GKE Autopilot-only or other GCP-specific constructs in manifests. |
| Infrastructure-as-Code | **OpenTofu** — full provisioning coverage (cluster, networking, IAM, storage, DNS); no manual click-ops setup (NOT Terraform — see Licensing note below) |
| Ingress (in front of the Go PEP) | **Gateway API**, implemented via **Envoy Gateway** (NOT `kubernetes/ingress-nginx` — see Licensing note below) |
| Observability | Prometheus + Grafana (metrics), Loki (ops/infra logs — distinct from the OpenSearch audit-log feature), OpenTelemetry (tracing across Kotlin/Go/Rust services) |
| CI/CD | ArgoCD (GitOps) — deploys from Helm chart desired-state, so target-cluster changes (SaaS → on-prem) are config changes, not re-tooling |

**Deliberately NOT used:** Cloud SQL, CSP-managed Redis/ElastiCache, GCP Certificate
Authority Service, GKE Autopilot-exclusive features, React Native (for the mobile
authenticator), MongoDB, a unified single-language backend, magic links, TLS-
inspecting proxy — all rejected specifically for the reasons captured in BRD Section
6 and the AP-5 portability requirement.

### Licensing & Sustainability Notes (do not substitute back without re-checking)

- **Valkey, not Redis.** Redis relicensed in 2024 to a dual RSALv2/SSPL model (not
  OSI-approved); Valkey is the Linux Foundation-governed BSD-3-Clause fork,
  wire-protocol compatible, with no usage restrictions.
- **OpenBao, not HashiCorp Vault.** Vault moved to the BUSL 1.1 license in 2023 and
  is now an IBM product. OpenBao is the Linux Foundation/OpenSSF-governed MPL 2.0
  fork, API-compatible, production-ready.
- **OpenTofu, not Terraform.** Same BUSL 1.1 issue as Vault. OpenTofu is the Linux
  Foundation MPL 2.0 fork, drop-in compatible with existing `.tf` configuration.
- **Gateway API / Envoy Gateway, not `kubernetes/ingress-nginx`.** This is not a
  license issue — the community Ingress NGINX project was retired by Kubernetes
  SIG Network in March 2026 (no more releases, bugfixes, or CVE patches, ever).
  Do not deploy it for a new project. Gateway API is the actively maintained
  Kubernetes-native successor to Ingress; Envoy Gateway is a CNCF, Apache
  2.0-licensed implementation of it. (Note: `nginxinc/kubernetes-ingress`, F5's
  separate product, is unaffected by the retirement but has a commercial tier —
  avoid it too, to keep the stack fully open-source.)
- **Grafana + Loki remain AGPLv3** (changed from Apache 2.0 in 2021) — this is
  still an OSI-approved open-source license. Its copyleft "network use" clause
  only applies if the source is modified and re-offered as a service to others;
  using it as internal observability tooling does not trigger that. No
  substitution needed, just be aware if anyone later proposes exposing a modified
  Grafana/Loki as a customer-facing feature.
- All other stack choices (Kotlin/Spring Boot, Go, Rust, Swift, React/Vite,
  Next.js, PostgreSQL, Kafka, OpenSearch, CloudNativePG, Helm, Kubernetes, ArgoCD,
  Prometheus, OpenTelemetry) were checked and remain permissively licensed
  (Apache 2.0 / MIT / PostgreSQL License / BSD) with no vendor lock-in or EOL
  concerns as of this writing.

## Commands

_Fill in once the repo is scaffolded: build, test, lint, run-locally commands per
service (Kotlin/Gradle, Go, Rust/Cargo, React/Vite, Next.js)._

