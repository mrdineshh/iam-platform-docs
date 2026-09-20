# IAM Platform — MVP Build Plan (Microservices, Standard Practice Edition)

**Read this file first, before writing any code.**

This is the final architecture decision: full microservices, built to real
industry-standard patterns — not a simplified toy version. Every pattern named
below is a deliberate, named choice, not an invented convention.

---

## 0. Working Agreement (READ THIS TWICE)

1. **Build ONE service per session.** Services are listed in Section 6, in
   dependency order. Build only the service named. Do not start the next one.
2. **Stop at the TEST GATE.** Print the exact commands to run, then stop and wait.
3. **Never modify a previously built service or its published contract**
   without explicit confirmation — a contract change can break every caller.
4. **Never call another service outside its published OpenAPI contract.**
5. **If something is underspecified, ask.** Do not invent scope.

---

## 1. Standard Patterns Used (name-checked, not invented)

| Pattern | What it solves | Where |
|---|---|---|
| **Database per service** | No service can silently depend on another's schema | Every service, own Postgres database |
| **Contract-first API design** (OpenAPI) | Services can't drift from what they promised to expose | `/contracts/*.yaml`, written before code |
| **Circuit breaker + retry** (Resilience4j) | One slow/down service can't cascade-fail the whole system | Every outbound inter-service call |
| **Event-driven audit logging** (Kafka) | Audit events survive a consumer being briefly down; new consumers (e.g. a future SIEM) can subscribe without touching publishers | `audit-events` Kafka topic |
| **Distributed tracing** (OpenTelemetry + correlation IDs) | One login request touches 6+ services — you need to see the whole trace, not 6 separate logs | Every service, propagated via `X-Correlation-Id` |
| **Health checks** (Spring Boot Actuator) | Standard `/actuator/health` (liveness) and `/actuator/health/readiness` shape, Kubernetes-compatible | Every service |
| **API versioning** | Contract changes don't break existing callers overnight | Every endpoint under `/api/v1/...` |
| **Config via environment** (12-factor) | No hardcoded URLs/secrets baked into images | `application.yml` + env vars + OpenBao |
| **Idempotency keys on mutating retries** | A retried request can't double-apply an effect | Session issuance, audit publish, device enrollment |

---

## 2. What We Are Building (MVP Scope)

```
Employee opens Grafana
  → iam-oidcprovider-svc redirects to iam-login-portal
  → login portal → iam-auth-svc (the login orchestrator)
  → iam-auth-svc → iam-directory-svc → Google Workspace confirms identity
  → iam-auth-svc → iam-policy-svc + iam-geo-svc: is this IP/location allowed?
  → iam-auth-svc → iam-device-svc: send push to phone
  → user taps Approve on iam-mobile-android
  → iam-auth-svc → iam-session-svc: issue session
  → every service along the way publishes to the audit-events Kafka topic
  → iam-oidcprovider-svc issues an OIDC token to Grafana
  → user is logged into Grafana
  → user's location changes to a blocked country mid-session
  → iam-enforcement-svc catches it on the next request, kills the session via
    iam-session-svc, publishes session.terminated to audit-events
```

### In scope
| Area | MVP choice |
|---|---|
| Upstream identity | Google Workspace via OIDC |
| Downstream app | One OIDC Service Provider (Grafana) |
| Location verification | IP-based, country-level (MaxMind GeoLite2) |
| User lifecycle | JIT provisioning + SCIM deprovisioning from Google Workspace |
| Second factor | Android app: TOTP + push approve/deny |
| Backend | 11 Kotlin + Spring Boot microservices (Section 5) |
| Web | Next.js login portal + React/Vite admin console |
| Mobile | Android (Kotlin) only |
| Data | PostgreSQL (one DB per service), Valkey, OpenBao, Kafka |
| Inter-service comms | Sync REST/JSON for request-response; Kafka for audit events |
| Observability | OpenTelemetry tracing, correlation IDs, Actuator health checks |

### Out of scope for MVP — DO NOT BUILD
- Endpoint agent (Rust), GPS, device trust/posture
- iOS app
- On-prem AD connector, ADFS, multi-directory
- Break-glass access, granular custom RBAC (two fixed roles for MVP)
- Reporting dashboards, SAML
- Service mesh (Istio/Linkerd), API gateway product (Kong) — production target
  is Envoy Gateway per the org's tech stack, but that's an infra/ingress concern
  layered on top later, not part of this build plan
- Full Kubernetes deployment — docker-compose for local dev; K8s manifests are
  a separate, later effort

---

## 3. Temporary MVP Deviations (log each to `/docs/DECISIONS.md`, `MVP-TEMPORARY`)

| # | Deviation | Target state | Why it's safe for now |
|---|---|---|---|
| D1 | `iam-enforcement-svc` is Kotlin, not Go | Go, per org tech stack | Separate service/repo already — only the language differs later |
| D2 | ~~Inter-service auth is a shared static secret header, not mTLS~~ **RESOLVED 2026-09-19** — real mutual TLS via OpenBao PKI + AppRole now enforced on the 4 purely-internal services (`iam-session-svc`, `iam-geo-svc`, `iam-identity-svc`, `iam-device-svc`); the other 5 services fetch a client cert too but keep plain-HTTP inbound listeners since they're reachable directly by browsers/Node that can't trust our self-signed CA | mTLS via OpenBao PKI | See `docs/DECISIONS.md`, mTLS rollout entry, for the full caller-graph analysis and simplifications (30-day cert/token TTL, no renewal daemon) |
| D3 | Two fixed roles instead of custom RBAC | Granular custom RBAC (FR-7.3) | Centralized in `iam-auth-svc`'s `AuthorizationService` |
| D4a | ~~Single-broker Kafka (no replication)~~ **RESOLVED 2026-09-19** — real 3-broker KRaft cluster, replication factor 3, `min.insync.replicas: 2`, producer `acks: all` | Multi-broker Kafka | See `docs/DECISIONS.md`, Kafka multi-broker entry |
| D4b | Single Postgres host (separate databases, not separate hosts), no redundancy | CloudNativePG per service, on Kubernetes | CloudNativePG is a Kubernetes operator — cannot be meaningfully replicated in docker-compose. Documented, not faked: see `infra/postgres/cloudnativepg-cluster.yaml` (deployment-time manifest, not yet applied) |
| D5 | SCIM sync is polling, not a real-time webhook | Google Admin SDK push notifications | Push requires a verified domain + public HTTPS endpoint; polling is a reasonable MVP tradeoff |

---

## 4. Service Boundary Rules

### 4.1 The services

| Service | Owns | Kafka role |
|---|---|---|
| `iam-audit-svc` | Audit event storage | **Consumes** `audit-events` |
| `iam-tenant-svc` | Tenant records | Produces to `audit-events` |
| `iam-geo-svc` | IP → country (stateless, no DB) | none |
| `iam-identity-svc` | User records, JIT provisioning | Produces to `audit-events` |
| `iam-policy-svc` | Policy model, merge-with-hard-cap resolver | Produces to `audit-events` |
| `iam-session-svc` | Session lifecycle (Valkey-backed) | Produces to `audit-events` |
| `iam-auth-svc` | Factor engine, **login orchestrator** | Produces to `audit-events` |
| `iam-directory-svc` | Google Workspace OIDC + SCIM sync | Produces to `audit-events` |
| `iam-device-svc` | Device enrollment, TOTP, push (FCM) | Produces to `audit-events` |
| `iam-enforcement-svc` | Continuous request-level enforcement (PEP) | Produces to `audit-events` |
| `iam-oidcprovider-svc` | Downstream OIDC provider | Produces to `audit-events` |
| `iam-mobile-android` | Authenticator app | — |
| `iam-login-portal` | Branded login UI (Next.js) | — |
| `iam-admin-console` | Tenant admin UI (React+Vite) | — |

`iam-auth-svc` is the named exception — it **orchestrates** the login sequence
across identity, policy, geo, session, directory, and device services. This
keeps AP-1 ("one auth engine") true even across service boundaries: one
service owns the sequence, nobody else may issue a session.

### 4.2 Contract-first: OpenAPI before code

```
iam-platform-docs/
├── docs/                       (BRD, CLAUDE.md, DECISIONS.md, this file)
├── contracts/
│   ├── iam-tenant-svc.yaml
│   ├── iam-geo-svc.yaml
│   ├── iam-identity-svc.yaml
│   ├── iam-policy-svc.yaml
│   ├── iam-session-svc.yaml
│   ├── iam-auth-svc.yaml
│   ├── iam-directory-svc.yaml
│   ├── iam-device-svc.yaml
│   ├── iam-enforcement-svc.yaml
│   ├── iam-oidcprovider-svc.yaml
│   └── audit-events.avsc        (Kafka message schema, Avro or JSON Schema)
└── docker-compose.yml
```

Every endpoint is versioned: `/api/v1/...`. A breaking contract change requires
a new version path (`/api/v2/...`) alongside the old one until callers migrate
— never an in-place breaking edit.

### 4.3 Repo layout — sibling folders

```
workspace/
├── iam-platform-docs/      (contracts/, docs/, docker-compose.yml)
├── iam-service-kit/        (shared technical infra only — see 4.5)
├── iam-tenant-svc/
├── iam-geo-svc/
├── iam-identity-svc/
├── iam-policy-svc/
├── iam-session-svc/
├── iam-auth-svc/
├── iam-directory-svc/
├── iam-device-svc/
├── iam-enforcement-svc/
├── iam-oidcprovider-svc/
├── iam-audit-svc/
├── iam-mobile-android/
├── iam-login-portal/
└── iam-admin-console/
```

### 4.4 Distributed tracing and correlation

Every inbound request either receives or generates an `X-Correlation-Id`
header. It propagates on every outbound call the request triggers — including
onto the Kafka message it publishes (as a message header, not just the body).
Every log line includes it. This is what makes "why did this login fail"
answerable in minutes instead of hours once six services are involved.

OpenTelemetry auto-instrumentation (Spring Boot starter) exports traces to a
local Jaeger or Zipkin container for MVP — a full Prometheus/Grafana/Loki stack
is a production concern, not required to prove the architecture locally.

### 4.5 Shared code — `iam-service-kit`, technical only

Allowed: Resilience4j-wrapped HTTP client, standard error DTO, Kafka
producer/consumer wrapper (with correlation-ID propagation baked in), OpenBao
client, Actuator health-check conventions.

Never allowed: `User`, `Policy`, `Session`, or any domain model. Each service
defines its own DTOs from the contract it implements — duplication here is the
price of independence, not a bug.

### 4.6 Resilience (Resilience4j, every inter-service call)

- **Circuit breaker:** trip after 5 consecutive failures, half-open retry
  after 30s cooldown
- **Retry:** exponential backoff with jitter, max 5 attempts, idempotent
  calls only
- **Timeout:** explicit per call, no unbounded waits — critical in
  `iam-enforcement-svc` and `iam-auth-svc`, both in the hot path
- **Graceful degradation, never fail-open:** e.g. `iam-geo-svc` unreachable →
  `iam-auth-svc` treats location as unresolved/high-risk, never an automatic pass
- **Kafka producer failures:** buffered + retried by the Kafka client itself;
  if genuinely unpublishable after retries, log locally and alert — never
  silently drop an audit event without at least a local trace of the failure

---

## 5. Non-Negotiable Principles

- **AP-1 — One auth engine.** All factors verified through `iam-auth-svc`'s
  single `AuthenticationEngine`. No other service issues a session.
- **AP-2 — Continuous enforcement.** `iam-enforcement-svc` re-validates policy
  on every request, independent of `iam-auth-svc`.
- **AP-3 — Never trust upstream directly.** `iam-directory-svc` resolves
  identity only, then hands off to `iam-auth-svc` — never issues a session itself.
- **AP-4 — Policy merge with hard-caps.** Lives entirely in `iam-policy-svc`.
- **AP-5 — Deployment-agnostic.** Plain containers, no cloud-vendor lock-in.
- **AP-8 — Audit everything security-relevant.** Every service publishes to
  `audit-events` for every security-relevant action it performs.

### Audit event schema (published to Kafka, consumed by `iam-audit-svc`)

| Field | Notes |
|---|---|
| `eventId` | UUID |
| `correlationId` | ties this event to the originating request across all services |
| `timestamp` | UTC, millisecond precision |
| `tenantId` | |
| `actorType` | `user` / `admin` / `system` / `agent` |
| `actorId` | |
| `action` | e.g. `auth.login_success`, `session.terminated` |
| `result` | `success` / `failure` / `denied` |
| `reason` | especially for `failure`/`denied` |
| `sourceIp`, `geo`, `deviceId` | where applicable |
| `policyScopeApplied` | `TENANT` / `OU` / `USER` |

---

## 6. Build Order (One Service Per Session)

### Service 0 — Shared foundation
- `/contracts/` folder + `audit-events` schema file
- `iam-service-kit`: Resilience4j-wrapped HTTP client, Kafka producer/consumer
  wrapper with correlation-ID propagation, OpenBao client, error DTO
- Root `docker-compose.yml`: Postgres (one DB per service via init scripts),
  Valkey, OpenBao, **Kafka (KRaft mode, single broker, no separate Zookeeper
  needed)**, Jaeger (tracing UI)
- Service template: Spring Boot + Actuator health endpoints + OpenTelemetry
  auto-instrumentation + `iam-service-kit` wired in, used to bootstrap every
  service below

**TEST GATE:** `docker compose up -d` — Postgres/Valkey/OpenBao/Kafka/Jaeger all
healthy. Service template boots, `/actuator/health` returns UP, a test message
round-trips through Kafka.

---

### Service 1 — `iam-audit-svc`
- **Consumes** `audit-events` from Kafka, writes to its own Postgres DB
- No outbound calls to any other service (this is what makes it safe to build
  first — nothing to depend on)
- Dead-letter topic (`audit-events-dlq`) for messages that fail processing
  after retries — never silently dropped

**TEST GATE:** publish a raw event to `audit-events` via `kafka-console-producer`
→ row appears in the audit database within seconds.

---

### Service 2 — `iam-tenant-svc`
- `POST /api/v1/tenants`, `GET /api/v1/tenants/{id}`
- Publishes `tenant.created` to `audit-events` on creation

**TEST GATE:** create a tenant → row in its DB → audit row appears in
`iam-audit-svc`'s database (first real Kafka-mediated integration proof).

---

### Service 3 — `iam-geo-svc`
- `GET /api/v1/resolve?ip=<ip>` → `{ country, region, city }`
- MaxMind GeoLite2 bundled in the container, stateless, no DB, no dependencies

**TEST GATE:** `curl` resolves a known IP to its correct country.

---

### Service 4 — `iam-identity-svc`
- `POST /api/v1/users`, `GET /api/v1/users/{id}`,
  `PATCH /api/v1/users/{id}/status`
- Calls `iam-tenant-svc` (Resilience4j-wrapped) to validate tenant existence
- Publishes `identity.created` / `identity.status_changed`

**TEST GATE:** create a user under a valid tenant → success + audit event.
Create under a nonexistent tenant → 404, nothing created (proves the
resilience-wrapped call actually validates, not just trusts input). Kill
`iam-tenant-svc` mid-test → circuit breaker trips, `iam-identity-svc` returns a
clear 503, doesn't hang.

---

### Service 5 — `iam-policy-svc`
- `PUT /api/v1/policies`, `POST /api/v1/evaluate`
- Pure logic + storage, no outbound calls — heaviest unit-test surface

**TEST GATE:** `./gradlew test` — merge behavior, hard-cap enforcement, exhaustive
coverage before any caller is wired to it.

---

### Service 6 — `iam-session-svc`
- `POST /api/v1/sessions`, `GET /api/v1/sessions/{token}`,
  `DELETE /api/v1/sessions/{token}`
- Valkey-backed, opaque tokens (never JWTs — enables the mid-flight kill later
  to be a direct lookup, not a revocation workaround)
- Publishes `session.issued` / `session.terminated`

**TEST GATE:** issue → validate → delete → validate again returns not-found,
each step's audit event visible in `iam-audit-svc`.

---

### Service 7 — `iam-auth-svc` — the login orchestrator
- `POST /api/v1/login` (password only for now), `POST /api/v1/logout`
- Orchestrates: `iam-identity-svc` → password check (Argon2id, OpenBao pepper)
  → `iam-geo-svc` + `iam-policy-svc` evaluate → `iam-session-svc` issue →
  publish outcome to `audit-events`
- Every call wrapped in Resilience4j; correlation ID generated here and
  propagated through the entire chain

**TEST GATE:** correct password + allowed location → session issued, full trace
visible in Jaeger showing all 4 downstream calls under one correlation ID.
Wrong password → 401 + `failure` event. Blocked-country IP → 403 + `denied`
event naming the policy. Kill `iam-session-svc` mid-test → login fails cleanly
with a 503, not a hang or a partial state.

**First real integration checkpoint** — six services, Kafka, and tracing all
proven together. Don't proceed until this is solid.

---

### Service 8 — `iam-directory-svc`
Setup (human, before this service): Google Cloud Console OAuth Client ID +
Admin SDK service account.

- `GET /api/v1/oauth/callback`, `POST /api/v1/sync` (SCIM polling trigger)
- On Google auth success: `iam-identity-svc` JIT-create, then **hands off to
  `iam-auth-svc`** to complete policy evaluation and session issuance — never
  calls `iam-session-svc` directly (AP-3)
- Validates the `hd` (hosted domain) claim against the tenant's Workspace domain
- SCIM: polls Google Admin SDK, calls `iam-identity-svc`'s status-patch
  endpoint for suspended/removed users, which cascades to session termination

**TEST GATE:** real Google Workspace login → JIT-created → session issued via
the proper `iam-auth-svc` path. Personal Gmail rejected via `hd` check.
Suspending a test user → next request denied, active session killed.

---

### Service 9 — `iam-device-svc`
- `POST /api/v1/devices/enroll`, `/totp/verify`, `/push/send`, `/push/respond`
- TOTP: AES-256-GCM, per-tenant DEK from OpenBao
- Push: FCM, pending-approval state in its own Valkey keyspace, 60s timeout
- Called by `iam-auth-svc` as a second-factor step in the same orchestrated
  login — no separate login endpoint (AP-1 preserved across the boundary)

**TEST GATE:** enroll via QR → TOTP accepted by `iam-auth-svc`'s login flow.
Push: login triggers a request here → phone approves → `iam-auth-svc` proceeds.

---

### Service 10 — `iam-enforcement-svc` (the PEP)
- On every protected request: calls `iam-session-svc` (valid?), `iam-geo-svc`
  (current location), `iam-policy-svc` (still allowed?)
- On violation: `iam-session-svc` delete + publish `session.terminated`
- Caches policy lookups briefly in Valkey to bound per-request overhead

**TEST GATE:** spoofed blocked-country IP on an active session → 401, session
gone, audit event recorded. Measure and record the added latency from 3
network hops — this is the concrete, visible cost of the architecture.

---

### Service 11 — `iam-oidcprovider-svc`
- `/authorize`, `/token`, `/userinfo`, `/.well-known/openid-configuration`,
  `/jwks.json`
- Calls `iam-auth-svc` to drive login, `iam-session-svc` to confirm validity,
  `iam-tenant-svc` for per-tenant client registration
- Signing keys in OpenBao, rotating JWKS

**TEST GATE:** full chain — Grafana → login portal → auth-svc → directory-svc →
policy/geo → device-svc push → session-svc → oidcprovider-svc → logged into
Grafana. Trigger a location violation mid-session → enforcement-svc kills it →
next Grafana request fails. Full trace visible end-to-end in Jaeger.

---

### Services 12–14 — Frontends
- `iam-mobile-android` — enrollment, TOTP, push approve/deny
- `iam-login-portal` (Next.js) — branded login, MFA states
- `iam-admin-console` (React+Vite) — tenant config, policy editor, audit viewer

---

## 7. Starter Files

### `docker-compose.yml` (infra layer, in `iam-platform-docs`)

```yaml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: iam
      POSTGRES_PASSWORD: localdev
    ports: ["5432:5432"]
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./infra/postgres-init:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U iam"]

  valkey:
    image: valkey/valkey:latest
    ports: ["6379:6379"]

  openbao:
    image: openbao/openbao:latest
    environment:
      BAO_DEV_ROOT_TOKEN_ID: dev-root-token
      BAO_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
    ports: ["8200:8200"]
    cap_add: ["IPC_LOCK"]

  kafka:
    image: apache/kafka:latest
    environment:
      KAFKA_NODE_ID: 1
      KAFKA_PROCESS_ROLES: broker,controller
      KAFKA_LISTENERS: PLAINTEXT://:9092,CONTROLLER://:9093
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092
      KAFKA_CONTROLLER_QUORUM_VOTERS: 1@kafka:9093
      KAFKA_CONTROLLER_LISTENER_NAMES: CONTROLLER
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR: 1
      KAFKA_TRANSACTION_STATE_LOG_MIN_ISR: 1
    ports: ["9092:9092"]

  jaeger:
    image: jaegertracing/all-in-one:latest
    ports: ["16686:16686", "4317:4317"]   # UI on 16686, OTLP gRPC on 4317

  # Appended as each service is built, e.g.:
  # iam-tenant-svc:
  #   build: ../iam-tenant-svc
  #   environment:
  #     DB_URL: jdbc:postgresql://postgres:5432/tenant_db
  #     KAFKA_BOOTSTRAP: kafka:9092
  #     OTEL_EXPORTER_OTLP_ENDPOINT: http://jaeger:4317
  #     BAO_ADDR: http://openbao:8200
  #   depends_on: [postgres, kafka, openbao]
  #   ports: ["8082:8080"]

volumes:
  pgdata:
```

### `iam-service-kit` — Kafka audit publisher

```kotlin
package com.iamplatform.servicekit.audit

import java.time.Instant
import java.util.UUID

enum class ActorType { USER, ADMIN, SYSTEM, AGENT }
enum class AuditResult { SUCCESS, FAILURE, DENIED }

data class AuditEvent(
    val eventId: UUID = UUID.randomUUID(),
    val correlationId: String,
    val timestamp: Instant = Instant.now(),
    val tenantId: UUID,
    val actorType: ActorType,
    val actorId: String,
    val action: String,
    val result: AuditResult,
    val reason: String? = null,
    val sourceIp: String? = null,
    val geo: String? = null,
    val deviceId: String? = null,
    val policyScopeApplied: String? = null,
)

/**
 * Every service publishes through this, never touches the Kafka producer
 * directly. Retry/backoff is the Kafka client's own producer config;
 * correlation-ID propagation happens here once, not reimplemented 11 times.
 */
interface AuditPublisher {
    fun publish(event: AuditEvent)
}
```

### `application.yml` per service

```yaml
iam:
  service-token: ${INTERNAL_SERVICE_TOKEN}
  dependencies:
    tenant-svc: http://iam-tenant-svc:8080
    policy-svc: http://iam-policy-svc:8080
    geo-svc: http://iam-geo-svc:8080
    session-svc: http://iam-session-svc:8080
  resilience4j:
    circuitbreaker:
      instances:
        default:
          failure-rate-threshold: 50
          sliding-window-size: 5
          wait-duration-in-open-state: 30s
    retry:
      instances:
        default:
          max-attempts: 5
          exponential-backoff-multiplier: 2

management:
  endpoints:
    web:
      exposure:
        include: health,info
  endpoint:
    health:
      probes:
        enabled: true    # exposes /actuator/health/liveness and /readiness

otel:
  exporter:
    otlp:
      endpoint: http://jaeger:4317

spring:
  kafka:
    bootstrap-servers: kafka:9092
```

---

## 8. Definition of Done (every service)

- [ ] Feature works end-to-end at its TEST GATE, with at least one real
      inter-service call and one real Kafka publish/consume proven live
- [ ] OpenAPI contract in `/contracts/<service>.yaml` matches implementation
- [ ] `/actuator/health/liveness` and `/readiness` both return correctly
- [ ] Negative-path tests exist, including a downstream dependency being down
      (circuit breaker trips, graceful degradation — not a crash)
- [ ] Correlation ID is propagated on every outbound call and every audit event
- [ ] Every state-changing action publishes an audit event with the full schema
- [ ] Own Dockerfile, own docker-compose entry, own Postgres database
- [ ] No hardcoded secrets — everything via `iam-service-kit`'s OpenBao client
- [ ] Any MVP deviation touched is logged in `/docs/DECISIONS.md`
- [ ] All previously built services still pass their tests unmodified
- [ ] Service README: ownership, contract, callers/callees, Kafka topics used

---

## 9. Session Prompt Template

> Read `BUILD_PLAN.md`. Build **Service N** only.
> Follow Section 4 (boundaries, contracts, resilience) and Section 5
> (principles) exactly. Write the OpenAPI contract before any implementation
> code. Use Resilience4j for outbound calls, propagate correlation IDs, expose
> Actuator health endpoints.
> Stop at the TEST GATE, print the exact commands I should run, and wait.
> Do not start the next service. Do not modify a previously built service or
> its published contract.
> If anything is underspecified, ask me instead of assuming.
