# iam-platform-docs

Umbrella documentation repo for the enterprise IAM platform (multi-tenant
SaaS, comparable in scope to Okta/Entra ID). This repo holds the
platform-wide product/architecture package; each service's own code lives
in its own repo per `CLAUDE.md`'s polyrepo model.

## Contents

| File | Purpose |
|---|---|
| `BUILD_PLAN.md` | **Current, authoritative build plan** — full-microservices MVP architecture, service boundaries, build order, TEST GATEs. Supersedes the module list in `CLAUDE.md` (see Status below). |
| `CLAUDE.md` | Original architecture principles (AP-1–AP-8), tech stack, repo list — still authoritative for AP-1–AP-8 and tech stack choices, superseded on service/module breakdown by `BUILD_PLAN.md` |
| `docs/BRD.md` | Business Requirements Document — full numbered FR/NFR set |
| `docs/ENGINEERING_GUARDRAILS.md` | Tier 1/2/3 decision framework, error-handling standard, audit schema, Definition of Done |
| `docs/DECISIONS.md` | Log of Tier-2/Tier-3 architectural decisions, with rationale and FR/BUILD_PLAN references |
| `docs/OPEN_QUESTIONS.md` | Tier-3 items awaiting human input — must be empty before a module/service is marked done |
| `docs/specs/` | Per-module specs written under the original `CLAUDE.md` workflow (pre-pivot) |
| `contracts/` | OpenAPI contracts + `audit-events.avsc`, one per service, written before implementation (`BUILD_PLAN.md` §4.2) |
| `docker-compose.yml` | Local dev infra: Postgres, Valkey, OpenBao, Kafka (KRaft), Jaeger |

## Status

- **Architecture pivot (2026-09-11):** the platform now follows `BUILD_PLAN.md`'s
  11-service microservices breakdown instead of `CLAUDE.md`'s original module
  list. See `docs/DECISIONS.md` ("Architecture pivot: BUILD_PLAN.md").
- **Service 0 (Shared Foundation): TEST GATE passed (2026-09-11).**
  `contracts/audit-events.avsc` and `docker-compose.yml` are in this repo;
  `iam-service-kit` and `service-template` exist as sibling repos under
  `C:\workspace\`. Both build cleanly (`./gradlew build`), `service-template`
  boots against the real running stack with `/actuator/health` returning
  `UP`, and a real message round-trips through the `audit-events` Kafka
  topic. Two real bugs were found and fixed along the way — see
  `docs/DECISIONS.md`.
- **Service 1 (`iam-audit-svc`): TEST GATE passed (2026-09-11).** Runs as a
  container (`C:\workspace\iam-audit-svc`, own `Dockerfile`, own `audit_db`
  Postgres database, own `docker-compose.yml` entry). Consumes `audit-events`,
  a valid message lands as a row within seconds; two deliberately malformed
  messages were retried and correctly routed to `audit-events-dlq` instead of
  being dropped. Three real bugs found and fixed — see `docs/DECISIONS.md`
  ("Service 1 — iam-audit-svc").
- **Service 2 (`iam-tenant-svc`): TEST GATE passed (2026-09-12).** Runs as a
  container (`C:\workspace\iam-tenant-svc`, own `Dockerfile`, own `tenant_db`
  Postgres database). `POST /api/v1/tenants` creates a tenant and publishes
  `tenant.created` to `audit-events`; the row shows up in `iam-audit-svc`'s
  database with the same correlation ID — the first proven Kafka-mediated
  integration between two services. `GET /api/v1/tenants/{id}`, the 404/409/400
  negative paths, and subdomain-uniqueness were all verified live. See
  `docs/DECISIONS.md` ("Service 2 — iam-tenant-svc").
- **Service 3 (`iam-geo-svc`): TEST GATE passed (2026-09-12).** Runs as a
  container (`C:\workspace\iam-geo-svc`), stateless, no database.
  `GET /api/v1/resolve?ip=<ip>` resolves known IPs to country/region/city.
  MVP-TEMPORARY: uses a small bundled test dataset instead of the real
  MaxMind GeoLite2 database (no license key available this session) — same
  contract either way, see `docs/DECISIONS.md` ("Service 3 — iam-geo-svc").
  That entry also covers a Docker networking failure hit during the build
  and the fix (official `gradle:9.7.1-jdk21` base image + BuildKit cache
  mount) recommended for all services from here on.
- **Service 4 (`iam-identity-svc`): TEST GATE passed (2026-09-12).** Runs as
  a container (`C:\workspace\iam-identity-svc`, own `identity_db`). First
  service with a real outbound call: validates a tenant exists (via a
  Resilience4j-wrapped call to `iam-tenant-svc`) before creating a user, and
  publishes `identity.created`/`identity.status_changed`. Two real
  circuit-breaker bugs were found and fixed here — the breaker never
  actually tripped (Resilience4j's `minimumNumberOfCalls` defaults to 100
  regardless of window size), and once fixed, calls stayed slow even after
  it opened (`Retry` was retrying `CallNotPermittedException` instead of
  failing fast). Both fixed and verified live, including a full
  stop/trip/fast-fail/recover cycle against a real killed dependency — see
  `docs/DECISIONS.md` ("Service 4 — iam-identity-svc").
- **Service 5 (`iam-policy-svc`): TEST GATE passed (2026-09-12).** The
  merge-with-hard-cap policy engine (AP-4). Pure logic, no outbound calls.
  MVP-TEMPORARY: implements only the country allow/block-list attribute (the
  one dimension the MVP demo flow exercises), scoped generically so more
  attributes can be added later without a redesign. `./gradlew test` — 18
  tests covering inheritance, override, and hard-cap-can't-be-overridden
  behavior across TENANT/OU/USER — all green; also verified live (hard-capped
  tenant block survives an OU's override attempt, `policy.updated` audit
  events confirmed). First service built with zero bugs found. See
  `docs/DECISIONS.md` ("Service 5 — iam-policy-svc").
- **Service 6 (`iam-session-svc`): TEST GATE passed (2026-09-13).** Runs as
  a container (`C:\workspace\iam-session-svc`), backed by Valkey, no
  database. Tokens are opaque and stored only as SHA-256 hashes, with an 8h
  TTL. Issue, validate, delete, and validate-again (`404`) all verified live,
  with `session.issued` and `session.terminated` audit events carrying the
  caller's correlation ID. Also verified: idempotent issuance (a retry
  returns the same token, no duplicate audit event), a clean bounded `503`
  when Valkey is down with automatic recovery, and a fix for missing-field
  requests returning a non-standard error body. See `docs/DECISIONS.md`
  ("Service 6 — iam-session-svc").
- **Tracing fix + session-token header move (2026-09-13).** Distributed
  tracing now actually works: fixed the OTLP/HTTP endpoint (was pointed at
  Jaeger's gRPC-only port, then at the wrong path once corrected) and
  raised sampling to 100% for local dev (Spring Boot's 10% default was
  swallowing test traffic). All six services now appear in Jaeger with real
  spans (HTTP, Redis, Kafka). Also moved `iam-session-svc`'s token from the
  URL path to an `X-Session-Token` header — confirmed live that the raw
  token no longer appears anywhere in exported traces — and fixed the
  missing-required-field error-body bug (found in Service 6) in
  `iam-tenant-svc`, `iam-identity-svc`, and `iam-policy-svc` too. Two
  services (`iam-audit-svc`, `iam-tenant-svc`) were also switched off the
  old wrapper-download Dockerfile pattern, which had started failing again.
  `docs/OPEN_QUESTIONS.md` is empty again. See `docs/DECISIONS.md`
  ("Tracing fix and session-token header move").
- **Service 7 (`iam-auth-svc`): TEST GATE passed (2026-09-13).** The login
  orchestrator (AP-1) — first real integration checkpoint. Password login
  calls `iam-identity-svc` → `iam-geo-svc` + `iam-policy-svc` →
  `iam-session-svc`, one correlation ID through all of it. Password
  ownership was added to `iam-identity-svc` (confirmed with the product
  owner first, since it changes an already-built service). Four real bugs
  found: `BAO_TOKEN` was never configured anywhere in the whole project
  (first service to actually use OpenBao for real reads/writes), Argon2
  hashing needs a BouncyCastle dependency nobody had added, and outbound
  resilience-wrapped calls were never actually traced or trace-linked
  because of two stacked Spring Boot 4 gotchas (a bare `RestClient.builder()`
  instead of the autoconfigured one, and a whole dedicated
  `spring-boot-starter-restclient` module Boot 4 requires for it to work at
  all). Fully verified live: correct login issues a session with a real
  5-service trace in Jaeger, wrong password → `401`, a hard-capped blocked
  country → `403` naming the policy, and killing `iam-session-svc` mid-login
  → bounded `503` that recovers cleanly. See `docs/DECISIONS.md`
  ("Service 7 — iam-auth-svc"). Service 8 (`iam-directory-svc`, Google
  Workspace OIDC) skipped for now — needs a Google Cloud Console OAuth
  client from the product owner first; built 9 and 10 instead since they
  have no external blocker.
- **Service 9 (`iam-device-svc`): TEST GATE passed (2026-09-16).** Second
  factor — TOTP (hand-rolled RFC 6238/4648, no new dependency) and FCM push
  approve/deny, one enrolled device record supports both. TOTP secrets and
  a per-tenant OpenBao-derived DEK, AES-256-GCM. TOTP fully verified live
  end-to-end through a real `iam-auth-svc` login, including the 5-attempt
  lockout. Push verified against a real Firebase project's credentials and
  device-svc's own fast-fail behavior; the final "phone taps Approve" hop
  needs a real Android device (Service 12, not built) to produce a genuine
  FCM token — same class of external blocker as Service 8. See
  `docs/DECISIONS.md` ("Service 9 — iam-device-svc").
- **Service 10 (`iam-enforcement-svc`): TEST GATE passed (2026-09-16).**
  The PEP (AP-2) — re-checks session, location, and policy on every
  protected request, independent of login. Never fails open: an unreachable
  policy/geo dependency denies just that one check without killing the
  session; a confirmed violation terminates it immediately. Verified live:
  a real session, spoofed into a blocked country, is denied and terminated
  in the same request, with both `enforcement.violation` and
  `session.terminated` audit events present. See `docs/DECISIONS.md`
  ("Service 10 — iam-enforcement-svc").
- **Service 11 (`iam-oidcprovider-svc`): TEST GATE passed (2026-09-17).**
  Lets a real third-party app use this platform as its login (standard
  OIDC Authorization Code flow) — the actual point of this milestone. No
  dependency on Services 8–10; built ahead of them at the product owner's
  request. Extended `iam-tenant-svc` with OIDC client registration (same
  pattern as extending `iam-identity-svc` for Service 7). At the time this
  was built, a minimal built-in login form stood in for `iam-login-portal`
  (Service 13, not yet built) and doubled as the fix for the real-IP
  problem flagged in Service 7, being the first genuine front door in the
  system. Both the form and that real-IP handling have since moved to
  Service 13 itself — see below. Access tokens never carry the raw platform
  session token; a
  server-side Valkey link lets `/userinfo` re-check session liveness on
  every call — confirmed live that killing a session immediately
  invalidates `/userinfo`, not just at the token's own expiry (the AP-2
  tie-in). Full round trip verified live with a real, independently
  computed TOTP code and real RS256-signed JWTs: client registration →
  `/authorize` → login → `/token` → `/userinfo`, plus the negative paths
  (unregistered redirect_uri never redirects, reused code and wrong secret
  both rejected). All ten services now appear in Jaeger under linked
  traces. See `docs/DECISIONS.md` ("Service 11 — iam-oidcprovider-svc").
- **Service 13 (`iam-login-portal`): TEST GATE passed (2026-09-17).**
  Real Next.js branded login UI, replacing Service 11's built-in placeholder
  form. `GET /authorize` now redirects here instead of rendering HTML;
  password + TOTP/push are entered on one combined screen (iam-auth-svc's
  `/login` has no separate "check password first" step) and submitted
  directly to `iam-auth-svc`; a new `POST /authorize/complete` on
  `iam-oidcprovider-svc` turns the resulting session token into an
  authorization code. The real-client-IP fix moves here from Service 11's
  form handler, since this is the actual front door now — a custom
  `server.js` reads the raw TCP socket, not a client-supplied header. Full
  round trip verified live *through the real rendered UI* (its actual React
  Server Action, submitted via the documented no-JS progressive-enhancement
  path, not mocked): password + independently-computed TOTP code → code →
  `/token` → `/userinfo`; killing the session re-confirmed the AP-2 tie-in
  through the new handoff. Two real bugs found and fixed (a `"use server"`
  export rule violation, and Node's dual-stack socket reporting an IPv4
  client as an IPv6-mapped address that iam-geo-svc's IPv4-only contract
  correctly rejected) — see `docs/DECISIONS.md` ("Service 13 —
  iam-login-portal").
- **Service 14 (`iam-admin-console`): TEST GATE passed (2026-09-18).**
  React + Vite SPA letting a tenant admin manage their own tenant's OIDC
  clients and access policy instead of raw `curl`. Introduced the
  platform's first real admin/role concept — nothing had one before this:
  `iam-identity-svc` gained a `role` field (`ADMIN`|`USER`) and a bootstrap
  `PATCH /users/{id}/role`; `iam-auth-svc`'s `LoginResponse` now carries
  `role`; `iam-tenant-svc` and `iam-policy-svc` each gained their own
  session-validating, role-checking `AdminAccessGuard` (first outbound
  HTTP calls either service makes). `iam-policy-svc`'s `PUT
  /api/v1/policies` — previously fully unauthenticated, arguably the most
  consequential open endpoint in the platform — was retrofitted with the
  same check, confirmed explicitly with the product owner first. Found and
  fixed a real gap invisible to `curl`-based testing: CORS was configured
  nowhere in the platform (never needed before — `iam-login-portal`'s
  calls are server-side, never subject to the browser's same-origin
  policy), which would have silently blocked every real browser request
  from this SPA; added to all three services it calls directly, verified
  live with a real preflight request. Verified live: a plain `USER` is
  correctly `403`'d on every admin-gated endpoint including the
  retrofitted `PUT`; promoting to `ADMIN` via the bootstrap endpoint then
  grants real access to list/create OIDC clients and view/edit policy,
  with a get-before-store 404 and a get-after-store round trip both
  confirmed. See `docs/DECISIONS.md` ("Service 14 — iam-admin-console") for
  the full bug list and known, deliberately-flagged gaps (the bootstrap
  role-promotion endpoint has no auth; a pure SPA can't learn its own real
  IP, so it sends a fixed local-dev-only placeholder that only works
  against `iam-geo-svc`'s existing private-IP fixture).
  Next: Service 8 (`iam-directory-svc`), still pending a Google Cloud
  Console OAuth client from the product owner; Service 12
  (`iam-mobile-android`) is the only remaining service.
- **Module 1 (Directory & Identity Sourcing + Authentication Policy Engine)**
  under the old plan: spec complete (`docs/specs/directory-auth-SPEC.md`),
  partial implementation was started in this repo and has been discarded (see
  `docs/DECISIONS.md`) — the equivalent functionality is now split across
  `iam-identity-svc` (Service 4) and `iam-auth-svc` (Service 7) per
  `BUILD_PLAN.md`.
- This repo (`iam-platform-docs`) currently still lives at
  `C:\Iam_core_Platform` on disk, not yet moved into `C:\workspace\` — see
  `docs/DECISIONS.md` for why.

## Workflow

Per `BUILD_PLAN.md`'s Working Agreement (§0): one service per session,
contract-first (OpenAPI/Avro before implementation), stop at each service's
TEST GATE, never modify a previously built service or its published contract
without confirmation, ask rather than assume when underspecified. Tier-3
decisions still go through `docs/OPEN_QUESTIONS.md` → resolved →
`docs/DECISIONS.md`, per `ENGINEERING_GUARDRAILS.md`.
