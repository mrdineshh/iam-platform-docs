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

---

## Architecture pivot: BUILD_PLAN.md (2026-09-11)

The single-module build order above (`iam-core-platform` as one Kotlin
monolith-per-module) is superseded by `BUILD_PLAN.md`'s full-microservices
architecture — 11 Kotlin/Spring Boot services plus frontends, one service per
session, contract-first. Confirmed with the user 2026-09-11. Entries below use
`[Service N]` / `[iam-service-kit]` tags instead of module names.

- **[Service 0] 2026-09-11** — `iam-service-kit` is consumed by every service
  via Gradle composite build (`includeBuild("../iam-service-kit")`), not a
  published Maven artifact — simplest for local MVP dev, no publish step
  required before a dependent service can pick up a kit change. Revisit if/when
  services are ever built independently in CI. Confirmed with the user.
  — BUILD_PLAN.md §4.5.

- **[Service 0] 2026-09-11** — Uncommitted Spring Boot/Gradle scaffolding that
  had been created directly inside the `iam-platform-docs` repo (this repo,
  currently still living at `C:\Iam_core_Platform` on disk) was discarded —
  confirmed with the user — since this repo is docs-only per its own
  `CLAUDE.md`/`README.md` and app code belongs in sibling service repos.

- **[Service 0] 2026-09-11** — Target repo layout is a `workspace/` parent
  containing `iam-platform-docs` plus one sibling folder per service
  (BUILD_PLAN.md §4.3), confirmed with the user. The physical move of this
  repo from `C:\Iam_core_Platform` into `C:\workspace\iam-platform-docs` is
  **deferred** — blocked by an IntelliJ IDEA process holding a lock on the
  directory. New repos (`iam-service-kit`, `service-template`) were created
  directly under `C:\workspace\` in the meantime; this repo's content and
  identity (`iam-platform-docs`) are unaffected by its current physical path.

- **[Service 0] 2026-09-11** — Concrete dependency versions pinned (live-
  checked against Maven Central / Spring Initializr on this date, since
  `CLAUDE.md`'s tech stack table names frameworks but not versions):
  Spring Boot `4.1.1`, Kotlin `2.3.21`, Gradle `9.7.1`,
  `org.springframework.boot:spring-boot-starter-webmvc` /
  `-kafka` / `-opentelemetry` (Spring Boot 4's own starter names/coordinates
  — `-kafka` and `-opentelemetry` are new first-party starters that didn't
  exist under Boot 3), `io.github.resilience4j:resilience4j-spring-boot3:2.3.0`.
  Resilience4j: chose the raw `resilience4j-spring-boot3` starter over Spring
  Initializr's offered `spring-cloud-starter-circuitbreaker-resilience4j`,
  because BUILD_PLAN.md §7's sample `application.yml` uses the raw
  `resilience4j.circuitbreaker.instances.<name>.*` / `resilience4j.retry.*`
  config keys directly, which only the raw starter's auto-configuration binds
  to — Spring Cloud's wrapper expects programmatic `Resilience4JConfigBuilder`
  customization instead. — BUILD_PLAN.md §1, §4.6, §7.

- **[Service 0] 2026-09-11** — `contracts/audit-events.avsc` implemented as a
  real Avro schema (not JSON Schema) to match the `.avsc` extension
  BUILD_PLAN.md §4.2 itself specifies for this file, with fields matching
  §5's table and the `AuditEvent` Kotlin shape given in §7.

- **[Service 0] 2026-09-11** — Correction to an earlier note in this same
  entry set: a JDK and Gradle *are* available on this machine, managed by
  IntelliJ under the user's profile (`~/.jdks/temurin-21.0.12.1`,
  `~/.gradle/wrapper/dists`) rather than on the shell's `PATH`. Using
  `JAVA_HOME=~/.jdks/temurin-21.0.12.1`, both `iam-service-kit` and
  `service-template` were actually built (`./gradlew build`) and
  `service-template` was booted (`./gradlew bootRun`) with
  `GET /actuator/health` confirmed returning `{"status":"UP"}` with
  liveness/readiness groups. One real compile bug was found and fixed in the
  process: `ResilientHttpClient`'s `get`/`post` were `inline fun <reified T>`
  bodies referencing the private `restClient` field (illegal — inline
  function bodies are copied to call sites outside the class) and depended on
  `io.github.resilience4j:resilience4j-decorators`'s `Decorators` builder,
  which isn't pulled in transitively by `resilience4j-spring-boot3`. Fixed by
  dropping `inline`/`reified` in favor of an explicit `Class<T>` parameter,
  and composing `Retry.decorateSupplier(retry, CircuitBreaker.decorateSupplier(...))`
  directly from `resilience4j-circuitbreaker`/`resilience4j-retry` (both are
  transitively included).

- **[Service 0] 2026-09-11** — Docker Desktop was started and
  `docker compose up -d` run against this repo's `docker-compose.yml`. Found
  and fixed a second real bug, this one in the starter file itself (present
  in `BUILD_PLAN.md` §7's sample too, fixed there as well): a single-broker
  KRaft Kafka container has no `KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR`
  override, so it defaults to requiring 3 replicas for the internal
  `__consumer_offsets` topic — impossible with 1 broker, and it silently
  breaks every consumer group (a produced message could never be read back).
  Fixed by setting `KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR` /
  `KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR` /
  `KAFKA_TRANSACTION_STATE_LOG_MIN_ISR` to `1`, matching D4's single-broker
  MVP deviation. After the fix: Postgres, Valkey, OpenBao, Kafka, and Jaeger
  all report healthy; a real message was produced to and consumed back from
  the `audit-events` topic via `kafka-console-producer`/`-consumer`; OpenBao's
  dev server responds unsealed; `service-template` was re-booted with
  `KAFKA_BOOTSTRAP=localhost:9092` / `BAO_ADDR=http://localhost:8200` pointed
  at the real running stack and stayed healthy. **Service 0's full TEST GATE
  now passes.**

---

## Service 1 — iam-audit-svc (2026-09-11)

- **No OpenAPI contract for this service.** `BUILD_PLAN.md` §4.2's contracts/
  listing enumerates a `.yaml` file for every other service but deliberately
  omits one for `iam-audit-svc` — it exposes no synchronous REST API for
  another service to call (Kafka-consumer-only, matching §6 Service 1's "no
  outbound calls to any other service"). Its only interface is
  `contracts/audit-events.avsc`, already written for Service 0. Treated as
  intentional, not an oversight, given how specifically that list is
  enumerated; not re-confirmed with the user since it's a straightforward
  reading of an already-approved document, not a new decision.

- **DB credentials via env vars, not OpenBao**, for local MVP Postgres access
  (`DB_URL`/`DB_USER`/`DB_PASSWORD`) — matches `BUILD_PLAN.md` §7's own
  starter `docker-compose.yml`, which passes `POSTGRES_PASSWORD` as a plain
  environment variable rather than routing it through OpenBao. OpenBao is
  still used for the pepper/signing-key/DEK material decided in the Module 1
  entries above; not every credential is OpenBao-brokered in the MVP.

- **Own Postgres database (`audit_db`)** created via
  `infra/postgres-init/01-init-databases.sql` for fresh volumes, and manually
  via `CREATE DATABASE audit_db;` against the already-existing `pgdata`
  volume from Service 0 (init scripts only run once, against an empty data
  directory).

- Three real bugs found and fixed while getting the TEST GATE to actually
  pass (all now fixed in `iam-audit-svc`, and the JDBC timezone + OTLP fixes
  were back-ported into `service-template` too so future services don't
  repeat them):
  1. **Postgres JDBC `TimeZone` startup failure.** Running the app directly
     on this Windows host failed with `FATAL: invalid value for parameter
     "TimeZone": "Asia/Calcutta"` — pgjdbc sends the JVM's default timezone ID
     as a connection startup parameter, and this Postgres image doesn't
     recognize that deprecated tzdata alias. Fixed with
     `-Duser.timezone=UTC` (Dockerfile `ENTRYPOINT`, and a `bootRun`
     `systemProperty` for host-side dev runs).
  2. **Kafka advertised-listener / Docker networking.** Running the app on
     the host with `KAFKA_BOOTSTRAP=localhost:9092` connects for the initial
     metadata fetch, but the broker's `KAFKA_ADVERTISED_LISTENERS` is
     `kafka:9092` — a hostname that only resolves inside the Docker network —
     so consumer-group coordination fails with `UnknownHostException` once
     the client tries to act on that metadata. Resolved by actually running
     `iam-audit-svc` as a container on the same Docker network (via its own
     `Dockerfile` + the `docker-compose.yml` entry), which is also the
     architecturally correct way to run it, not a workaround.
  3. **OTLP metrics exporter misconfigured.** Micrometer's `OtlpMeterRegistry`
     defaulted to pushing metrics over HTTP to `jaeger:4317`, which is a
     gRPC-only port on Jaeger's all-in-one image — every push cycle logged a
     `Failed to publish metrics` warning. First attempted fix
     (`otel.metrics.exporter: none`) was the wrong property — that's an OTel
     SDK/vendor-agent property, but this is Micrometer's own registry.
     Correct fix: `management.otlp.metrics.export.enabled: false`. MVP only
     requires tracing (`BUILD_PLAN.md` §4.4); metrics/Prometheus is a later
     concern.

- **TEST GATE passed and verified twice**: a well-formed `AuditEvent` JSON
  produced via `kafka-console-producer` appears as a row in
  `audit_db.audit_events` within seconds. Additionally verified the negative
  path unprompted: two malformed messages (missing required fields; a raw
  epoch-millis `timestamp` instead of ISO-8601) were retried per
  `KafkaConsumerConfig`'s `ExponentialBackOffWithMaxRetries(5)` and correctly
  routed to `audit-events-dlq` rather than silently dropped or crashing the
  consumer — proving Guardrails §2's dead-letter requirement, not just the
  happy path.

---

### Service 2 — iam-tenant-svc (2026-09-12)

- **Contract:** `contracts/iam-tenant-svc.yaml` — `POST /api/v1/tenants`,
  `GET /api/v1/tenants/{id}`, written before implementation per Section 4.2.
- **Tenant data model (MVP-TEMPORARY, not asked/not in BRD schema form):**
  `id` (UUID), `name`, `subdomain` (unique, lowercase/alphanumeric/hyphen,
  pattern-validated), `status` (`ACTIVE`/`SUSPENDED`), `createdAt`. Branding
  (FR-6.1), custom RBAC (FR-7.3–7.4), and multi-directory config (FR-2.9) are
  explicitly deferred to their own services/tables later — this is only what
  `BUILD_PLAN.md` Section 6's Service 2 scope requires (subdomain existence
  for FR-6.2's subdomain-only login, nothing else yet).
- **Audit event actor identity (Tier-2, decided not asked):** `tenant.created`
  is published with `actorType=SYSTEM`, `actorId="iam-tenant-svc"`. No admin
  authentication/RBAC exists yet at this point in the build order (that's
  `iam-auth-svc`, Service 7, and the admin console, Service 14) — there is no
  real actor identity to attribute the call to yet. Revisit once an
  authenticated admin path exists to create tenants; this is a placeholder,
  not a design decision to keep long-term.
- **Validation belongs to the service, not the kit:** added
  `spring-boot-starter-validation` (bean validation on `CreateTenantRequest`)
  directly to `iam-tenant-svc`, not to `iam-service-kit` — Section 4.5 scopes
  the kit to technical/cross-cutting infra only, and request-shape validation
  is service-specific business logic.
- **Bug found during TEST GATE:** the first tenant-creation test showed zero
  rows in `audit_db` despite a 201 response. Root cause was operational, not
  code: `iam-audit-svc`'s container had not been (re)started this session —
  only the base infra (`postgres`/`kafka`/`openbao`/`jaeger`) had been brought
  up before building `iam-tenant-svc`. This is exactly the durability
  guarantee Kafka is supposed to provide (Section 1's "Event-driven audit
  logging" pattern): once `iam-audit-svc` was started, the `tenant.created`
  event for the tenant created *before* the consumer existed was still
  delivered and landed correctly, proving the message wasn't lost, only
  unconsumed. No code change was required.
- **Transient infra failure:** the first `docker compose build` attempt for
  `iam-tenant-svc` failed with a Gradle-distribution download timeout inside
  the build container (`SocketTimeoutException`, same class of Docker
  networking flakiness seen in Service 0/1). A plain retry of the same build
  succeeded — logged for pattern-recognition, not a code fix.

**TEST GATE passed:** `POST /api/v1/tenants` with a valid body → `201` +
row in `tenant_db.tenants` + a `tenant.created` row in `audit_db.audit_events`
(same request's `correlationId` present on both, tying the trace together).
`GET` on the created ID → `200` with matching fields. `GET` on a random UUID →
`404`. `POST` with an already-used subdomain → `409`, no duplicate row, no
audit event published. `POST` with an invalid subdomain (uppercase/spaces) →
`400` with a field-level validation message. Verified against the real
running stack (Postgres, Kafka, OpenBao, Jaeger), not mocked.

---

### Service 3 — iam-geo-svc (2026-09-12)

- **Contract:** `contracts/iam-geo-svc.yaml` — `GET /api/v1/resolve?ip=<ip>`.
- **MVP-TEMPORARY (confirmed with product owner, 2026-09-12):** `BUILD_PLAN.md`
  calls for the real MaxMind GeoLite2 database bundled in the container.
  MaxMind now requires a free-account license key to download it, which
  wasn't available in this session. Per the product owner's explicit choice,
  this service instead ships a small bundled test dataset
  (`src/main/resources/geoip/ip-ranges.json`, four IPv4 CIDR ranges) behind
  the exact same contract, so the API shape, resilience behavior, and every
  downstream caller built against it do not need to change when the real
  GeoLite2 `.mmdb` is swapped in later — only `GeoLookupService`'s data
  source changes. IPv6 is not supported by the bundled matcher yet (also
  deferred to the real GeoLite2 integration). One of the four bundled ranges,
  `203.0.113.0/24` (RFC 5737 TEST-NET-3, permanently reserved and never
  publicly routed), is deliberately mapped to a synthetic country (`KP`) as a
  safe, stable fixture for exercising geo-blocked-country policy tests in
  later services (Section 6, Service 5/7) — this is a test fixture, not a
  real geo claim about that range.
- **`resolved: false` is a normal 200, not an error:** an IP outside the
  dataset returns `200` with null country/region/city and `resolved: false`,
  not a `404`. This matches Section 4.6's graceful-degradation rule — callers
  (eventually `iam-auth-svc`) must treat an unresolved location as
  high-risk/unknown, never as an automatic pass, and a normal 200 response
  makes that an expected branch to handle, not an exceptional one.
- **No Kafka publishing:** per Section 4.1's table, `iam-geo-svc`'s Kafka role
  is explicitly "none" — a geo lookup is a supporting data fetch, not itself
  a security-relevant action to audit (AP-8 concerns the decision made using
  this data, which happens in the calling service). `iam-service-kit`'s
  `AuditPublisher` bean is still on the classpath (transitively, since the
  kit's own `build.gradle.kts` declares Kafka as an `api` dependency) but is
  never injected or called here.
- **Bug found during TEST GATE — repeated Docker build network failures.**
  The image build failed four times in a row downloading the Gradle wrapper
  distribution (`services.gradle.org`, `SocketTimeoutException`/`Connect
  timed out`), despite a plain container being able to reach the same host
  fine. Rather than keep retrying blind: switched the build stage's base
  image from `eclipse-temurin:21-jdk` + Gradle Wrapper to the official
  `gradle:9.7.1-jdk21` image (Gradle pre-installed, no wrapper download at
  all), and added a BuildKit cache mount (`--mount=type=cache,target=/root/
  .gradle`) so Maven Central dependency downloads persist across builds
  instead of being fetched fresh in every service's image. The very next
  build attempt still hit a transient `Network is unreachable` partway
  through resolving dependencies (the same class of Docker Desktop network
  drop seen earlier in Service 0/1/2) — a second retry with the now-warm
  cache succeeded in under 2 minutes. **Recommendation for Service 4
  onward:** use this same `gradle:9.7.1-jdk21` + cache-mount Dockerfile
  pattern from the start, rather than the wrapper-download pattern used by
  Services 1-2, to avoid repeating this failure mode.

**TEST GATE passed:** `GET /api/v1/resolve?ip=8.8.8.8` → `200`,
`{"country":"US","region":"California","city":"Mountain View","resolved":true}`.
Second known range (`1.1.1.1` → `AU`) and the synthetic test-net range
(`203.0.113.5` → `KP`) both verified. An IP outside the dataset (`5.5.5.5`) →
`200` with `resolved:false` and null fields (not an error). A malformed IP
(`not-an-ip`) → `400`. A missing `ip` query parameter → `400`. Verified
against the real running container, not mocked.

---

#### Service 3 addendum — real geo data swap (2026-09-16)

- **Replaced the bundled test dataset with DB-IP Lite (Country edition),**
  not MaxMind GeoLite2 as `BUILD_PLAN.md` originally specified. GeoLite2
  requires a MaxMind account + license key (still not set up); DB-IP Lite is
  free with no account/key/EULA gate, ships in the same MaxMind DB binary
  `.mmdb` format, and is read with the open-source `com.maxmind.db:maxmind-db`
  reader library. Only `GeoLookupService`'s internals changed — contract,
  resilience behavior, and callers are untouched. Confirmed with product
  owner before starting (scope explicitly limited to the geo data swap; a
  separate, deeper gap — `iam-auth-svc` trusting a client-supplied IP instead
  of detecting the real one — was explicitly deferred, still pending the
  gateway/front-door service, Section 6 Service 11/13).
- **Country-only, region/city now always null.** DB-IP's free tier has no
  sub-country granularity. Confirmed acceptable because `iam-policy-svc`
  only implements country-based policy — no caller reads region/city today.
- **Removed the `203.0.113.0/24` → `KP` synthetic test fixture** along with
  the whole bundled `ip-ranges.json` dataset and the hand-rolled
  `IpRangeMatcher`. Checked first: `iam-auth-svc` and `iam-session-svc`'s
  tests stub `GeoClient` directly with hardcoded `GeoResolution` values (e.g.
  `country = "KP"`) and never call the real `iam-geo-svc` over the network,
  so no downstream test depended on this fixture's actual dataset content —
  safe to remove. The service's own unit test for "unresolved" now uses
  `203.0.113.5` on its RFC-5737-reserved merit alone (never publicly routed,
  so real geo data has no entry for it), not as a synthetic country mapping.
  `5.5.5.5` is no longer a valid "outside dataset" fixture either — it's a
  real, allocated French range in actual geo data.
- **License note:** DB-IP Lite is CC BY 4.0 (attribution required, added to
  `iam-geo-svc/README.md`). The bundled `.mmdb` file is a dated snapshot
  (2026-09-16) and will go stale; DB-IP publishes a new file monthly and the
  file should be refreshed periodically — not automated in this session, to
  avoid scope creep beyond the requested data swap.
- **TEST GATE (re-verified with real data):** unit tests re-run against the
  actual bundled `.mmdb` (no mocking of the reader) — all pass. Also
  verified live against a running container: `GET /api/v1/resolve?ip=8.8.8.8`
  → `200 {"country":"US","region":null,"city":null,"resolved":true}`;
  `1.1.1.1` → `AU`; `203.0.113.5` → `resolved:false`, null fields; malformed
  IP and missing `ip` param → `400`.

---

### Service 4 — iam-identity-svc (2026-09-12)

- **Contract:** `contracts/iam-identity-svc.yaml` — `POST /api/v1/users`,
  `GET /api/v1/users/{id}`, `PATCH /api/v1/users/{id}/status`.
- **First service with a real outbound dependency:** `TenantClient` calls
  `GET /api/v1/tenants/{id}` on `iam-tenant-svc` through `iam-service-kit`'s
  `ResilientHttpClient` before creating a user — the only way this service is
  allowed to touch tenant data (Section 4.4, no direct DB access).
- **User data model (Tier-2, not asked):** `id`, `tenantId`, `email`,
  `displayName`, `status` (`ACTIVE`/`SUSPENDED`), `createdAt`. `(tenant_id,
  email)` is unique — consistent with the Module 1 interview's confirmed
  identity-collision default of matching on email (2026-08-03 entry above).
  Google-subject-ID and other directory-linkage fields are deliberately not
  added yet; that's `iam-directory-svc` (Service 8)'s concern when it starts
  JIT-provisioning through this service.
- **Bug found — circuit breaker never actually opened.** The first resilience
  test (stopping `iam-tenant-svc` and hammering `POST /api/v1/users`)
  produced a steady `503` on every call but at a *constant* ~2.1s each --
  never the fast, sub-100ms fail an OPEN circuit breaker is supposed to give.
  Root cause: Resilience4j's `minimumNumberOfCalls` defaults to **100**
  regardless of `sliding-window-size`, so a breaker configured with only
  `failure-rate-threshold` + `sliding-window-size` (exactly the shape used in
  `BUILD_PLAN.md`'s own Section 7 sample, and in `service-template`'s
  Service-0 config) never accumulates enough calls to evaluate the failure
  rate in realistic testing -- it silently never trips. Fixed by adding
  `minimum-number-of-calls: 5` explicitly to the `tenant-svc` circuit breaker
  instance. Confirmed via `/actuator/circuitbreakers` (temporarily exposed
  for debugging, reverted after): state flipped `CLOSED` -> `OPEN` after
  exactly 5 buffered calls, as intended. **Flag for later services:** any
  circuit breaker instance should set `minimum-number-of-calls` explicitly,
  not rely on defaults -- `service-template`'s Section-0 config likely has
  the same latent gap, left unmodified per the "don't touch a previously
  built service without confirmation" rule, but worth fixing when Service 0
  is next revisited.
- **Second bug found — the breaker opened, but calls still took ~2.1s
  instead of failing fast.** Root cause: this codebase's `ResilientHttpClient`
  composes `Retry` around `CircuitBreaker` (Retry is outermost), so once the
  breaker is `OPEN`, each retry attempt still gets a
  `CallNotPermittedException` thrown by the inner breaker -- and Resilience4j's
  `Retry` retries on *any* exception by default, so it kept retrying an
  exception that means "don't bother," burning the full backoff schedule
  every call. Fixed by adding
  `io.github.resilience4j.circuitbreaker.CallNotPermittedException` to the
  `tenant-svc` retry instance's `ignore-exceptions` list, alongside the
  existing `HttpClientErrorException$NotFound` entry. After the fix: first
  failing call (breaker still closed) bounded at ~10s (real retries against a
  dead endpoint); every call after the breaker opens completes in ~110-150ms.
  **Flag for later services:** any service wrapping a Resilience4j `Retry`
  around a `CircuitBreaker` must add `CallNotPermittedException` to the
  retry's ignore list, or the same silent slow-fail bug will recur.
- **Also confirmed recovery, not just failure:** after restarting
  `iam-tenant-svc` and waiting out the 30s `wait-duration-in-open-state`, the
  breaker went `HALF_OPEN` and the very next real call succeeded (`201`),
  proving the system self-heals without a restart.

**TEST GATE passed:** `POST /api/v1/users` under a real tenant → `201` + a
`identity.created` row in `audit_db.audit_events`. Under a nonexistent tenant
→ `404`, no row created (proves the resilience-wrapped call genuinely
validates, not just trusts the input). `GET` on the created ID → `200`;
unknown ID → `404`. Duplicate email within the same tenant → `409`. `PATCH
.../status` → `200` + `identity.status_changed` row with the `ACTIVE ->
SUSPENDED` transition in `reason`. Killing `iam-tenant-svc` mid-test: first
call fails bounded (~10s, not a hang), circuit breaker flips `OPEN` after 5
buffered calls, every subsequent call fails in ~110-150ms instead of
hanging or slow-retrying. Restarting `iam-tenant-svc` and waiting out the
cooldown → breaker self-heals, next real request succeeds. All verified
against the real running stack, not mocked.

---

### Service 5 — iam-policy-svc (2026-09-12)

- **Contract:** `contracts/iam-policy-svc.yaml` — `PUT /api/v1/policies`,
  `POST /api/v1/evaluate`.
- **MVP-TEMPORARY scope narrowing (Tier-2, not asked):** BRD FR-4.1 lists
  IP, geo-location, and device policies at three levels. This service
  implements only the country allow-list/block-list attribute pair — the one
  dimension `BUILD_PLAN.md`'s own MVP demo flow (Section 2) actually
  exercises via `iam-geo-svc`. IP-range and device-trust attributes are
  deferred; the merge/hard-cap engine (`PolicyEvaluator`) is written
  attribute-generically (`resolveAttribute` takes any tenant/OU/user triple),
  so adding a new attribute later means adding another call to it, not
  redesigning it.
- **Storage shape (Tier-2):** one `policies` table, one row per
  `(tenant_id, scope, scope_id)` — for `scope=TENANT`, `scope_id` is set to
  `tenant_id` itself (not left null), specifically so the unique index
  `(tenant_id, scope, scope_id)` actually enforces "one tenant-level policy
  row per tenant" -- Postgres treats `NULL <> NULL`, so a nullable `scope_id`
  would have silently allowed duplicate tenant-level rows. Country lists are
  stored as comma-joined `TEXT`, not a Postgres array/JSONB column -- there
  are only two list attributes in the MVP schema, not worth any Hibernate
  array-type mapping risk for this size of problem.
- **Hard-caps only settable at `scope=TENANT`** (`400` otherwise) -- matches
  BRD FR-4.2, "tenant admins may mark specific policies as hard-caps"; there
  is structurally no such concept below the tenant level.
- **`POST /api/v1/evaluate` does not publish an audit event per call** (Tier-2,
  not asked): this sits on the hot path of every login and continuous
  enforcement check (AP-2); the calling service (`iam-auth-svc`,
  `iam-enforcement-svc`) is what records the resulting security-relevant
  outcome (e.g. `auth.login_denied`, `session.terminated`) with full context.
  `PUT /api/v1/policies` (a config change) does publish `policy.updated` --
  confirmed live, including a real audit row for both a `TENANT`-scope and an
  `OU`-scope update, each with the correct `policyScopeApplied`.
- **No bugs found this service** -- first service built after committing to
  the `gradle:9.7.1-jdk21` + cache-mount Dockerfile pattern from the start;
  the image built and started successfully on the very first attempt.

**TEST GATE passed (per BUILD_PLAN.md's own definition for this service):**
`./gradlew test` — 18 tests, all green, covering: no-policy-configured
(default allow), plain tenant block-list and allow-list, OU overriding
tenant when it defines the attribute vs. inheriting when it doesn't, user
overriding OU overriding tenant, a tenant hard-cap surviving an OU's and a
user's attempt to override it (both the block-list and allow-list cases,
including proving the hard-cap *replaces* rather than *merges with* the
lower level's value), block-list-beats-allow-list precedence when a country
is in both, and the service-layer validation (`scopeId` required for
OU/USER, hard-cap flags rejected outside TENANT, update-not-duplicate on a
repeated `PUT`). Additionally verified live against the real container: a
tenant-level hard-capped block on `KP` denies `KP` and allows `US`; an OU
then tries to additionally block `US` and is correctly ignored (hard-cap
proven live, not just in the unit test); both `PUT`s produced real
`policy.updated` rows in `iam-audit-svc`'s database with the correct
`policyScopeApplied`.

---

### Service 6 — iam-session-svc (2026-09-13)

- **Contract:** `contracts/iam-session-svc.yaml`, covering
  `POST /api/v1/sessions`, `GET /api/v1/sessions/{token}`, and
  `DELETE /api/v1/sessions/{token}`.
- **Storage:** Valkey only, through `spring-boot-starter-data-redis`. That
  starter name was checked against the Spring Boot 4.1.1 BOM, not assumed.
  There is no Postgres database, so no `session_db`.
- **Session lifetime (Tier-2, not asked):** absolute TTL of `8h`, set by
  `iam.session.ttl` (env `SESSION_TTL`). Neither the BRD nor the Module 1
  spec specifies a session lifetime. No idle timeout yet. Continuous
  revalidation belongs to `iam-enforcement-svc` (Service 10).
- **Tokens stored hashed (Tier-2):** tokens are 256 bits of `SecureRandom`
  output, base64url-encoded. Each session is keyed as
  `session:<sha256(token)>`, so a dump of the session keyspace yields no
  usable bearer tokens. A plain SHA-256 is enough because the input is
  random, not a guessable password. Verified live: the raw-token key
  doesn't exist, the hashed key does, and its TTL is about 28,800 seconds.
- **Idempotency-Key on issuance:** BUILD_PLAN.md §1 lists session issuance
  as requiring idempotency keys. A retry with the same key, tenant, and user
  within `10m` returns the original session and sets
  `Idempotent-Replayed: true`. The key is claimed atomically (`SET NX`)
  *before* issuing, so concurrent retries can't both issue. Reusing a key
  for a different user returns `409`. A replayed key whose session has
  since been terminated also returns `409`, rather than issuing a new
  session.
- **Termination is atomic:** DELETE uses `GETDEL`, so two concurrent
  terminations publish exactly one `session.terminated`.
- **`DELETE ...?reason=` query parameter (additive, Tier-2):** not in
  BUILD_PLAN's endpoint list, but `iam-enforcement-svc` needs to record
  *why* it killed a session (AP-2). The reason goes into the audit event.
- **Audit event shape:** `actorType=USER` and `actorId=<userId>`, because
  the session's subject is the "who" AP-8 needs. `sourceIp` and `deviceId`
  are carried through. `AuditEvent` has no session field, so the session
  ID goes into `reason` (`sessionId=...` or `sessionId=...; <reason>`).
  The token itself is never logged or audited.
- **Bounded Valkey timeouts:** `spring.data.redis.timeout: 2s` and
  `connect-timeout: 2s`. Lettuce's default command timeout is 60s, which
  would break §4.6's "no unbounded waits."
- **Error bodies redact the token:** any error on
  `/api/v1/sessions/<token>` reports `path` as `/api/v1/sessions/{token}`.
- **Not done (flagged, not invented):** nothing yet restricts who may call
  `POST /api/v1/sessions`. AP-1 intends only `iam-auth-svc`, and that
  arrives with deviation D2's shared-secret inter-service header, which no
  service implements yet.
- **Bug found: missing required fields returned a non-standard error body.**
  `POST` without `userId` returned Spring's default
  `{timestamp,status,error,path}` body, with no `message` and no
  `correlationId`. Cause: Kotlin non-null request fields make Jackson
  reject the body while reading it, raising
  `HttpMessageNotReadableException` before bean validation runs, and no
  handler covered that exception. Fixed with a dedicated handler returning
  the standard `ErrorResponse`. Verified live for both a missing field and
  malformed JSON; the caller-supplied correlation ID comes back.
- **Transient build failure:** the first image build failed after about 5
  minutes. It was the first build that needed the Redis/Lettuce/Netty
  dependencies inside the Docker cache mount. The exact error was lost
  because the log had been piped through `tail`. A rebuild, with the cache
  already partly filled, succeeded in 59s. Probably the same network flake
  as Service 3, but unconfirmed.
- **The same missing-field bug is confirmed live in three earlier
  services, and is not fixed there.** A body with a required field missing
  returns Spring's default error body, with no `message` and no
  `correlationId`, from `iam-tenant-svc` (`POST /api/v1/tenants`),
  `iam-identity-svc` (`POST /api/v1/users`), and `iam-policy-svc`
  (`POST /api/v1/evaluate`). This was never caught because their TEST
  GATEs only exercised `MethodArgumentNotValidException` (a present but
  invalid field), not a missing one. Each fix is the same one-handler
  change made here. Left unmodified per the working agreement's "never
  modify a previously built service without confirmation."
- **Platform-wide finding raised here: tracing has never worked.** Logged
  as OQ-1 in `docs/OPEN_QUESTIONS.md`, and not fixed, because it touches
  every previously built service. OQ-2 (tokens in URL paths reaching traces)
  depends on it.

**TEST GATE passed:** issue → `201`, with a 43-character token. Validate →
`200`. Delete with `?reason=logout` → `204`. Validate again → `404`. A second
delete → `404`. In `audit_db`: exactly one `session.issued`, carrying
correlation ID `gate-issue-001`, and exactly one `session.terminated`,
carrying `gate-delete-001` and reason `...; logout`. The double DELETE did
not produce a second event. Also verified live:
- An idempotent retry returns the same token with the replay header, and
  exactly one `session.issued` exists for that user.
- Same key with a different user → `409`.
- Valkey stopped → `GET` and `POST` both return `503` in about 2.2s, with
  health `DOWN`.
- Valkey restarted → automatic recovery (unknown token → normal `404`,
  health `UP`).
- After the error-handler fix, the full cycle was re-run with no
  regression.

All against the real running stack, not mocked.

---

### Tracing fix and session-token header move (2026-09-13)

Follow-up to the Service 6 entry above. Product owner confirmed: fix OQ-1
and the missing-field error-body bug across all services now, and resolve
OQ-2 by moving the session token to a header before `iam-auth-svc` (Service
7) starts calling `iam-session-svc`.

- **OQ-1, tracing endpoint:** every service's `application.yml` and
  `docker-compose.yml` `OTEL_EXPORTER_OTLP_ENDPOINT` changed from
  `http://jaeger:4317` (gRPC-only) to `http://jaeger:4318` (OTLP/HTTP),
  under the corrected property key
  `management.opentelemetry.tracing.export.otlp.endpoint` (the old
  `otel.exporter.otlp.endpoint` / `otel.service.name` keys were never real
  Spring Boot properties -- dead config, now removed. Service name is
  already derived from `spring.application.name` automatically). Also
  published Jaeger's `4318` port to the host in `docker-compose.yml` for
  manual debugging.
  - **First attempt was wrong and caught before being called done:** setting
    the endpoint to the full `http://jaeger:4318/v1/traces` produced a live
    `404` from Jaeger (confirmed in logs), because Spring Boot's OTLP/HTTP
    tracing exporter appends `/v1/traces` itself -- the property wants the
    *base* URL. Corrected to `http://jaeger:4318` and reverified.
- **OQ-1, second half -- sampling:** after the endpoint fix, zero spans
  still reached Jaeger, with *no* export errors at all (a different symptom
  from before). Root cause: `management.tracing.sampling.probability`
  defaults to `0.1` in Spring Boot -- a handful of manual test requests
  essentially never gets sampled. Set to `1.0` in every service, since the
  entire point of local tracing here is seeing every request's full trace
  (BUILD_PLAN.md §4.4), not approximating production sampling. Confirmed
  live: `GET /api/v1/services` on Jaeger's API now lists all six IAM
  services, and `iam-session-svc`'s trace includes real spans for the HTTP
  request, the Redis `set`/`get`/`getdel` calls, and the Kafka publish --
  a genuine end-to-end trace, not a stub.
- **Two services were still on the old wrapper-download Dockerfile
  pattern and failed to rebuild:** `iam-audit-svc` (Service 1) and
  `iam-tenant-svc` (Service 2) predate the `gradle:9.7.1-jdk21` +
  cache-mount fix adopted from Service 3 onward (see that entry). Both hit
  the same Gradle-wrapper download timeout again here. Switched both
  Dockerfiles to the same pattern as every other service -- a build
  mechanism change only, no contract or runtime behavior change, so it
  doesn't fall under "never modify a previously built service" in spirit,
  though it does touch their source tree; logged here for visibility.
- **Building all six services' images in one `docker compose up -d
  --build` call fails under Gradle cache-lock contention.** BuildKit runs
  independent service builds in parallel by default, and all six were
  hitting the identical `--mount=type=cache,target=/root/.gradle` cache
  simultaneously, so Gradle's own journal-cache file lock serialized them
  into a timeout. Fixed by building one service at a time
  (`docker compose build <svc>` in a loop) instead of one combined command.
  Worth remembering for any future "rebuild everything" pass.
- **OQ-2, session token moved to a header:** `iam-session-svc`'s contract
  and implementation changed from `GET/DELETE /api/v1/sessions/{token}` to
  `GET/DELETE /api/v1/sessions` with the token in a required
  `X-Session-Token` header. This is a contract change to a previously
  "done" service, made only because (a) the product owner explicitly
  authorized it and (b) no caller exists yet (`iam-auth-svc` is Service 7,
  not yet built), so nothing breaks. `GlobalExceptionHandler`'s path-redaction
  hack was removed as no longer needed, and a `MissingRequestHeaderException`
  handler added so a missing token returns the standard `ErrorResponse`
  shape, not Spring's default. Verified live: a full issue/validate/delete
  cycle over the header still works, a missing header returns `400`, and --
  the actual point of this fix -- zero occurrences of the raw token appear
  anywhere in `iam-session-svc`'s exported Jaeger trace (checked by
  generating a token and grepping the trace export for it directly, not
  inferred).
- **Missing-field error body bug, confirmed fixed in three more services:**
  the same `HttpMessageNotReadableException` handler added to
  `iam-session-svc` in the prior entry was added to `iam-tenant-svc`,
  `iam-identity-svc`, and `iam-policy-svc`. Verified live on all three: a
  request missing a required field now returns the standard `ErrorResponse`
  shape (with `message` and the caller's `correlationId`), not Spring's
  bare default body. Regression-checked: normal field-present-but-invalid
  validation (`MethodArgumentNotValidException`) still returns its own
  distinct message on `iam-tenant-svc`.

All fixes rebuilt and reverified against the real running stack (not just
recompiled) before being called done.

---

### Service 7 — iam-auth-svc (2026-09-13)

- **Contract:** `contracts/iam-auth-svc.yaml` — `POST /api/v1/login`,
  `POST /api/v1/logout`. Owns no data of its own; pure orchestration
  (no Postgres, no Flyway).
- **Password ownership moved to iam-identity-svc (confirmed with product
  owner before starting, per AskUserQuestion):** BUILD_PLAN.md's own
  orchestration sequence names `iam-identity-svc` for the password check,
  but Service 4 (already TEST-GATE-passed) had no password field at all.
  Extended it rather than storing credentials in `iam-auth-svc`, matching
  "iam-identity-svc owns user records" and avoiding splitting one entity's
  data across two services' databases. Added: `password_hash` column,
  optional `password` on `CreateUserRequest`, `PATCH /api/v1/users/{id}/password`,
  and `POST /api/v1/users/verify-password` (always `200`; `valid:false` with
  no `userId`/`status` covers both "no such user" and "wrong password"
  identically -- deliberate, prevents user enumeration). `verify-password`
  publishes no audit event itself, same reasoning as `iam-policy-svc`'s
  `evaluate` (Service 5): `iam-auth-svc` is what makes and records the
  actual security decision.
- **Argon2id + pepper (Tier-2, deviates from the 2026-08-03 decision):**
  hashing uses the confirmed params (m=19456 KiB, t=2, p=1) via Spring
  Security's `Argon2PasswordEncoder`, but the pepper is a single
  platform-wide value in OpenBao's KV v2 engine (get-or-create on first use),
  not a per-tenant value via OpenBao Transit's HMAC operation as the
  original interview decided. Transit needs bootstrap tooling (enabling the
  engine, creating a key) this MVP doesn't have, and there's no
  tenant-onboarding flow yet to provision one pepper per tenant. Flagged for
  before real deployment.
- **Never fail open (BUILD_PLAN.md Section 4.6), made concrete:** identity-svc
  or session-svc being unreachable returns `503` (a real infra failure,
  nothing else to do). geo-svc or policy-svc being unreachable is instead
  folded into a `403` denial with a specific reason -- their entire purpose
  is a risk gate, so "the gate is down" must default to closed, not to
  "skip the check." `AuthService` catches `CallNotPermittedException`/
  `ResourceAccessException` around only those two calls; identity/session
  failures are deliberately left to propagate to `GlobalExceptionHandler`.
- **Idempotency-Key reused, not reinvented:** `iam-session-svc`'s issuance
  idempotency mechanism (built in Service 6) is used here with the
  request's own correlation ID as the key, so a Resilience4j retry after a
  timeout can't issue two sessions for one login.
- **Kit addition -- `ResilientHttpClient.post`/new `.delete` accept optional
  headers:** needed for the `Idempotency-Key` header on session issuance and
  the `X-Session-Token` header on logout. Additive, default-valued, doesn't
  break `TenantClient` (Service 4), the only prior caller.
- **Kit addition -- `OpenBaoClient.readSecretOrNull` / `.writeSecret`:**
  needed for the get-or-create pepper. Additive to the existing `readSecret`.
- **Bug found -- `BAO_TOKEN` was never set anywhere, for any service.**
  Every service's `docker-compose.yml` entry set `BAO_ADDR` but not
  `BAO_TOKEN`, so `OpenBaoClient` sent an empty Vault token on every call --
  a `403 permission denied` the moment anything actually called
  `readSecret`/`writeSecret` for real. This had been latent since Service 0;
  it was never caught because **no service before this one ever actually
  exercised OpenBao** (every prior `iam.openbao.*` config was wired but
  unused). Fixed by adding `BAO_TOKEN: dev-root-token` (the dev-mode root
  token already defined for the `openbao` container) to all seven services'
  `docker-compose.yml` entries.
- **Bug found -- `Argon2PasswordEncoder` threw `NoClassDefFoundError` at
  runtime.** `spring-security-crypto` declares BouncyCastle as an optional
  dependency; Argon2 needs it, nothing pulled it in. Fixed by adding
  `org.bouncycastle:bcprov-jdk18on:1.79` as `runtimeOnly` to
  `iam-identity-svc`.
- **Bug found -- none of the outbound resilience-wrapped calls were
  actually traced, and didn't propagate trace context to the callee.**
  Verified via Jaeger: `iam-auth-svc`'s own inbound `/api/v1/login` span
  existed, but the 4 downstream calls it makes were completely invisible --
  not slow, not failed, just never instrumented, so Service 7's TEST GATE
  ("full trace visible in Jaeger showing all 4 downstream calls under one
  correlation ID") could not be satisfied. Root cause:
  `resilientRestClientBuilder` called the static `RestClient.builder()`
  directly instead of using Spring's autoconfigured, prototype-scoped
  `RestClient.Builder` bean -- only the autoconfigured one carries the
  `ObservationRestClientCustomizer` that creates client spans and injects
  `traceparent`. This bug existed since Service 4 (`TenantClient`), just
  never noticed because nobody had checked whether that specific call was
  traced. Fixed by changing `resilientRestClientBuilder`'s signature to
  require an injected `RestClient.Builder` (breaking-but-mechanical change,
  every call site updated: `TenantClient` plus the four new auth-svc
  clients). **Second bug surfaced while fixing the first:** even with a
  constructor-injected `RestClient.Builder`, both services failed to start
  with "no bean of type RestClient.Builder found" -- Spring Boot 4 moved
  `RestClient` autoconfiguration into its own dedicated
  `spring-boot-starter-restclient` module (the same split-into-new-starters
  pattern already seen for webmvc/Kafka/OpenTelemetry). Fixed by adding it
  as an `api` dependency directly on `iam-service-kit` (not each service),
  since `ResilientHttpClient` is exactly the kit-owned piece that needs it,
  and every future service gets a correctly-traced HTTP client automatically
  as a result. Confirmed fixed by pulling a real login trace from Jaeger's
  API and finding 11 spans across `iam-auth-svc`, `iam-identity-svc`,
  `iam-geo-svc`, `iam-policy-svc`, and `iam-session-svc`, all under one
  trace ID.

---

### Service 9 — iam-device-svc (2026-09-16)

Built out of the original numbered order (Service 8/`iam-directory-svc` is
still blocked on Google Workspace admin access) since Service 9 has no
external blocker. Second-factor device enrollment and verification: TOTP +
FCM push approve/deny.

- **Contract:** `contracts/iam-device-svc.yaml` — `POST /api/v1/devices/enroll`,
  `/totp/verify`, `/push/send`, `/push/respond`.
- **One device, both factors (confirmed with product owner):** a single
  enrolled device row carries both the TOTP secret and (optionally) an FCM
  token, rather than separate enrollments per factor. "The" device for a
  tenant/user is always the most recently enrolled row.
- **totp/verify and push/send are keyed by tenantId+userId, not deviceId:**
  `iam-auth-svc` only ever knows tenantId+userId at login time (a user
  doesn't carry their own device UUID around), so both endpoints look up
  "the" device themselves rather than requiring the caller to know it.
  `push/respond` is keyed by challengeId alone, since that's what the
  mobile app receives via the push payload.
- **Push/send blocks synchronously up to 60s (confirmed with product
  owner):** matches BUILD_PLAN.md listing only 4 endpoints, no polling
  endpoint. `iam-auth-svc`'s `DeviceClient` uses a 65s read timeout for this
  call specifically (`resilientRestClientBuilder`'s `readTimeout` param),
  not the platform-default 5s.
- **TOTP lockout added (confirmed with product owner):** not explicitly
  specified in BUILD_PLAN.md's Service 9 section, but a 6-digit code
  without rate-limiting is quickly brute-forceable. 5 failed attempts locks
  the device for 5 minutes (`iam.device.totp.max-failed-attempts` /
  `lock-duration`, both configurable). Modeled as a normal `200` response
  (`status: LOCKED`), not a `4xx` — same "expected branch, not exceptional"
  style as `iam-geo-svc`'s `resolved:false`.
- **Per-tenant TOTP DEK via OpenBao KV, not Transit:** AES-256-GCM key
  generated and cached per-tenant, get-or-create against OpenBao's KV v2
  engine (`totp-dek/<tenantId>`) — same pattern as `iam-identity-svc`'s
  password pepper (Service 7), just keyed per-tenant instead of
  platform-wide. BUILD_PLAN.md only requires the DEK be OpenBao-held, not
  specifically routed through Transit; Transit still has no bootstrap
  tooling in this MVP (same reasoning as the pepper's own deviation).
- **TOTP algorithm and base32 hand-rolled, not a new dependency:** RFC 6238
  (HMAC-SHA1, 6 digits, 30s step, ±1 step drift window) and RFC 4648 base32
  are both small, long-standardized algorithms — implementing them directly
  avoided two new third-party dependencies. Verified against RFC 6238's own
  published test vectors and RFC 4648's base32 test vector, not just
  round-trip self-tests.
- **FCM dependency (Tier-3, confirmed with product owner 2026-09-16):**
  `com.google.auth:google-auth-library-oauth2-http` added — not in
  CLAUDE.md's tech stack table, needed sign-off before adding (Guardrails
  Section 1, Tier 3, "new third-party dependency" rule). Used only for the
  OAuth2 token exchange from the service-account JSON; the actual FCM send
  is a plain REST call through the project's own `ResilientHttpClient`, not
  the full `firebase-admin` SDK (rejected: pulls in gRPC and other Firebase
  products this platform doesn't use).
- **FCM credential handoff (Tier-3, confirmed with product owner):** the
  product owner saved the service-account JSON locally and gave the
  assistant session its file path; a one-time script read that local file
  and wrote it into OpenBao (`fcm-service-account`, field `json`) via the
  KV v2 API against the running dev-mode container. The raw key contents
  were never pasted into the conversation itself. `FcmCredentialsProvider`
  reads it from OpenBao at first use, same as every other secret in this
  platform; never from a local file at runtime.
- **`iam-auth-svc` contract change (confirmed with product owner before
  proceeding, per the "never modify a previously built service's contract
  without confirmation" rule):** `LoginRequest` gains an optional
  `totpCode` field. Present → `AuthService` calls `iam-device-svc`'s TOTP
  verify. Absent → falls through to the blocking push/send instead. No
  separate MFA login endpoint (AP-1 preserved across the service boundary).
  Second factor is unconditionally required in this MVP — BUILD_PLAN.md's
  login flow diagram calls `iam-device-svc` unconditionally, with no
  policy-driven skip; whether MFA is even possible is entirely data-driven
  (does this user have an enrolled device), not a hardcoded separate path.
- **Known gap, logged rather than silently shipped: no retry on
  `iam-auth-svc`'s calls to `iam-device-svc`.** `totp/verify` (increments a
  failed-attempt counter, can trigger lockout) and `push/send` (sends a
  real notification, creates a Valkey challenge) are both mutating, and
  neither has an idempotency key the way `iam-session-svc`'s `issue`
  endpoint does (Service 7). Retrying either on a lost response (not a
  rejected request) risks double-counting a failed TOTP attempt toward
  lockout, or firing a duplicate push notification for one login attempt.
  Fixed by setting `device-svc`'s Resilience4j retry `max-attempts: 1` in
  `iam-auth-svc` (no retry) rather than the platform-default 5 — fail the
  login closed and let the user retry the whole login, rather than risk a
  double-applied side effect. Should be revisited with a proper idempotency
  key if/when this moves past MVP.
- **`device_db` created manually, not via `infra/postgres-init`:** that
  init script only runs against an empty Postgres data directory (see its
  own header comment); the `pgdata` volume already existed from Services
  1-7, so `CREATE DATABASE device_db;` was run directly against the live
  container. The init script was still updated so a fresh environment
  bootstraps correctly.

**TEST GATE passed (TOTP path, fully live, verified twice):** enrolled a
real user via `POST /devices/enroll`, activated the device with a TOTP
code computed from the returned secret via `POST /devices/totp/verify`,
then logged in through the real `iam-auth-svc` `/api/v1/login` with that
same TOTP code and confirmed a session was issued. Lockout verified live:
5 wrong codes in a row → `LOCKED`, and the correct code is still refused
while locked. `push/respond`'s own validation verified live (`404` for an
unknown challenge). Full audit trail (`device.enrolled`,
`device.totp_verified` success/failure, `device.locked`, `auth.login_*`)
confirmed by querying `audit_db` directly, not just trusting the HTTP
response. Both `iam-device-svc`'s and `iam-auth-svc`'s full Gradle test
suites (15 and 17 tests respectively) run for real in a JDK container, not
just compiled.

**Push path — partially live-verified, one honest gap remains:** the real
FCM credential's OAuth2 auth and IAM permission were confirmed working
end-to-end against the actual `testing-ratnesh` Firebase project (two real
GCP issues found and fixed along the way — see below). `device-svc`'s own
error handling was confirmed live: sending to a syntactically-invalid
placeholder token correctly fails fast (~6s, via Resilience4j) with a `503`
rather than hanging for the full 60s wait. What could **not** be
live-verified: a genuine "phone taps Approve → `iam-auth-svc` proceeds"
round trip, because that requires a real FCM registration token, which only
an actual Android device running the Mobile Authenticator app can produce
— that app is Service 12, not built yet. This isn't a hidden gap: it's the
same class of externally-blocked verification as Service 8's Google
Workspace dependency, just discovered one service later than expected.
The polling/approve/deny/timeout *logic* itself (not the FCM delivery) is
covered by `DeviceServiceTest`'s mocked-FCM unit tests.

**Two real GCP issues found and fixed while verifying push (not code
bugs, environment/account setup):**
1. Firebase Cloud Messaging API was disabled on the `testing-ratnesh` GCP
   project — first attempt failed with `SERVICE_DISABLED`. Fixed by the
   product owner enabling it in Cloud Console.
2. The service account being used (`vertex-express@testing-ratnesh...` —
   a Vertex AI credential, not a dedicated Firebase Admin SDK key) lacked
   the `cloudmessaging.messages.create` permission even after the API was
   enabled. Fixed by the product owner granting it the
   `roles/firebasecloudmessaging.admin` IAM role directly, rather than
   generating a separate dedicated Firebase key — same credential, wider
   grant.

**Operational finding, cross-cutting (not a Service 9 bug):** mid-session,
Docker Desktop itself stopped and had to be relaunched twice. Each time,
OpenBao's dev-mode container came back with **all secrets wiped** —
dev mode never persists to disk, so a container restart (not just the app
inside it) resets it to empty. This silently broke password verification
for every previously-created test user (`iam-identity-svc`'s pepper,
Service 7, was regenerated fresh and no longer matches old password
hashes) and orphaned any previously-enrolled device's encrypted TOTP
secret (the per-tenant DEK backing it was gone too). Not a defect
introduced by this service — the same get-or-create-in-OpenBao-KV pattern
already existed for the pepper — but this is the first session that
happened to restart OpenBao mid-work and surface it. Recovered each time
by reloading the FCM credential and creating a fresh test user; no code
change made. Worth remembering before any future real (non-dev-mode)
OpenBao deployment, and worth remembering *during* local dev too: don't
assume enrolled devices/passwords survive a Docker Desktop restart.

**TEST GATE passed:** correct password + allowed location (`8.8.8.8` → no
policy configured) → `200`, session issued, `session.issued` +
`auth.login_success` audit rows, full 5-service trace confirmed in Jaeger
under one trace ID. Wrong password → `401` + `auth.login_failure`. A
tenant-wide hard-capped block on `KP`, login from the synthetic
`203.0.113.5` test-net IP → `403` naming the exact policy reason
(`country 'KP' is in blockedCountries`) and scope (`TENANT`) in both the
response and the `auth.login_denied` audit event. Killing `iam-session-svc`
mid-test → login fails bounded at ~10.3s (not a hang) with a clean `503`;
restarting it and retrying → `200`, proving the whole chain recovers without
a restart of `iam-auth-svc` itself. All verified against the real running
seven-service stack, not mocked.

---

### Service 10 — iam-enforcement-svc (2026-09-16)

The PEP. Built next after Service 9 (Service 8/`iam-directory-svc` remains
blocked on Google Workspace access) since Service 10 has no external
blocker.

- **Contract:** `contracts/iam-enforcement-svc.yaml` — `POST /api/v1/enforce`.
  BUILD_PLAN.md describes this service's behavior ("on every protected
  request: calls session-svc, geo-svc, policy-svc") but not a concrete
  endpoint shape, unlike every other service. Designed and confirmed with
  the product owner before writing the contract: `X-Session-Token` header
  (matches `iam-session-svc`'s own convention) + `{sourceIp}` body (same
  client-supplied-IP MVP-TEMPORARY gap as `iam-auth-svc`'s `LoginRequest`,
  duplicated here for the same reason — still no gateway/front-door service
  to derive it server-side). Single `POST /enforce` returns `200 {allowed}`
  or `401` for any denial reason (never a distinct 4xx per case) —
  confirmed as the simplest shape matching the literal TEST GATE wording.
- **Uses the CURRENT request's sourceIp, not the session's login-time
  sourceIp, for the geo/policy check.** This is the entire point of
  continuous enforcement (AP-2) — checking where the request is coming
  from *now*, not where the user was at login. The session's original
  `sourceIp` is only ever used as session metadata (returned by
  `iam-session-svc`), never re-checked against policy.
- **Policy-decision cache keyed by `(tenantId, userId, country)`, not just
  `(tenantId, country)` as first proposed and confirmed with the product
  owner** — corrected during implementation for correctness: a tenant-only
  cache key would silently ignore per-user OU/USER-scope policy overrides
  (AP-4) and could serve one user a decision computed for a different
  user's policy. 30s TTL as confirmed. Session validity itself is never
  cached, by design — only the policy decision, which is what "bound
  per-request overhead" in BUILD_PLAN.md actually refers to.
- **Three denial cases collapsed to one `401`, but audited differently
  (Tier-2, following existing graceful-degradation precedent from
  `iam-auth-svc`):**
  1. Unknown/expired/terminated session → **no audit event.** Unlike every
     other denial case, there is no tenantId/userId to attribute one to —
     the token didn't resolve to anything. Matches `iam-identity-svc`'s
     `verifyPassword` precedent (Service 4/7): don't fabricate an audit
     record around an identity that was never established.
  2. Location unresolved, or `iam-policy-svc` unreachable → audited
     (`enforcement.check_denied`, `DENIED`), but the session is **not**
     terminated. A transient dependency blip denies this one request; it
     does not destroy the user's whole session, mirroring exactly how
     `iam-auth-svc` treats the same two failure modes at login (deny this
     attempt, don't lock the account).
  3. A confirmed policy violation (the real AP-2 scenario) → session
     terminated via `iam-session-svc` first, *then* audited
     (`enforcement.violation`, `DENIED`, with the policy's own reason and
     `policyScopeApplied`). `iam-session-svc` independently publishes its
     own `session.terminated` event on the same termination — both are
     expected to appear; this service audits that *it detected and acted
     on* the violation, `iam-session-svc` audits the mechanical
     termination itself.
- **A successful (`200 allowed`) check publishes no audit event at all** —
  deliberate, not an oversight. An allowed check is the expected,
  high-frequency default (every single protected request that isn't a
  violation), not itself a security-relevant event. Follows
  `iam-policy-svc`'s own `evaluate` endpoint precedent (Service 5): the
  caller that acts on a decision is what records it. Auditing every allow
  would drown the audit log at real request volume.
- **`iam-service-kit` addition — `ResilientHttpClient.get` gains an
  optional `headers` parameter** (default `emptyMap()`), matching the
  `post`/`delete` methods added in Service 7. Needed to send
  `X-Session-Token` on the `GET /api/v1/sessions` validate call. Additive,
  default-valued — doesn't change any existing caller (`GeoClient` in
  `iam-geo-svc`'s callers, `iam-auth-svc`, and now this service).
- **No Postgres database.** Unlike most other services, this one has no
  data of its own to own — stateless except for the Valkey policy cache.
- **PEP-specific Definition of Done (Guardrails Section 4):** ran a basic
  latency check — first `/enforce` call for a given session/country
  (policy cache miss, full `iam-session-svc` + `iam-geo-svc` +
  `iam-policy-svc` round trip) vs. subsequent calls within the 30s cache
  window (policy cache hit, skips the `iam-policy-svc` call entirely).
  See the TEST GATE result below for the actual numbers.

**Bug found and fixed while verifying the TEST GATE -- double-encoded
termination reason.** `SessionClient.terminate`'s query string reason had
been manually `URLEncoder.encode`'d since Service 7 -- harmless until now,
because every prior termination reason ("logout", "unspecified") had no
characters that needed escaping. The first reason containing a quote
("country 'DE' is in blockedCountries") exposed it: `RestClient.uri(String)`
treats the string as a URI template and encodes it itself, so the
already-percent-escaped value got encoded a second time; the server's
single `@RequestParam` decode pass only undid one layer, leaving literal
`%27` sequences stored in the audit log. Fixed by removing the manual
`URLEncoder.encode` call and passing the raw reason string, letting
`RestClient` encode it exactly once -- correct in both `iam-enforcement-svc`
(new) and `iam-auth-svc`'s identical, pre-existing `SessionClient.terminate`
(Service 7, fixed here since it's the same bug in the same copy-pasted
method). Confirmed via a live re-run of the TEST GATE below.

**TEST GATE passed, live, against the real running stack:**
- Logged in for real through `iam-auth-svc` (TOTP path) to get a real
  session token. `POST /enforce` with the session's actual login IP
  (8.8.8.8, US) -> `200 {allowed:true}`.
- Configured a real `blockedCountries: ["DE"]` policy via `iam-policy-svc`.
  `POST /enforce` on the same still-active session with a spoofed IP that
  resolves to Germany (5.5.5.5) -> `401 {"message":"country 'DE' is in
  blockedCountries"}`. Immediately re-checking the identical session with
  its original, still-allowed IP -> `401 "session not found, expired, or
  terminated"` -- proving the session was actually destroyed, not just
  this one request denied.
- Audit trail confirmed by querying `audit_db` directly: `enforcement.violation`
  (DENIED, policyScopeApplied TENANT, the exact policy reason) and
  `session.terminated` (SUCCESS, now with the correctly-decoded reason
  after the bug fix above) both present.
- Confirmed the "unresolved location" path separately (a 203.0.113.5 check
  denied with "location could not be verified", session left alive) --
  this is also what incidentally exposed that Service 3's real geo-data
  swap (docs/DECISIONS.md, Service 3 addendum) means the old
  203.0.113.0/24 -> KP synthetic fixture no longer resolves to anything; a
  real country block (DE) was needed to exercise the actual violation
  path, confirming that removal was correctly scoped and didn't leave a
  hidden dependency anywhere.
- **PEP-specific latency check (Guardrails Section 4):** first `/enforce`
  call for a session/country pair (policy cache miss) vs. ten subsequent
  calls (policy cache hits, confirmed present in Valkey via
  `policy-cache:<tenant>:<user>:<country>`) -- all calls landed in the
  ~100-195ms range with no growth over repeated calls, i.e. bounded,
  non-degrading per-request overhead. Not a rigorous load test, but
  confirms the cache is doing real work, not dead code.
- `iam-enforcement-svc`'s full test suite (7 tests) run for real via
  Gradle in a JDK container, not just compiled. `iam-geo-svc`'s test suite
  re-run afterward as a regression check on the shared `iam-service-kit`
  change above -- still green.

---

### Service 11 — iam-oidcprovider-svc (2026-09-17)

Built ahead of Service 8 at the product owner's explicit request: it has no
real dependency on Services 8-10 (only calls `iam-auth-svc`, `iam-session-svc`,
`iam-tenant-svc`, all already built), and unblocks connecting a real
third-party app now rather than waiting on a Google Cloud Console setup step.

- **Contract:** `contracts/iam-oidcprovider-svc.yaml` --
  `/authorize`, `/authorize/login`, `/token`, `/userinfo`,
  `/.well-known/openid-configuration`, `/jwks.json`. These five are
  deliberately NOT under `/api/v1` -- they're standardized OIDC/OAuth2 paths
  (RFC 8414) generic client libraries expect at exact fixed locations; a
  documented exception to Section 4.2's versioning rule, required by the
  spec itself, not a scope choice.
- **Extended iam-tenant-svc (confirmed acceptable before starting, same
  pattern as extending iam-identity-svc for Service 7):** added OIDC client
  registration (`oidc_clients` table, `POST/GET /api/v1/oidc-clients`,
  `POST .../verify-secret`). Lives here, not in this service, because
  BUILD_PLAN.md itself names `iam-tenant-svc` as the owner of "per-tenant
  client registration," and a client registration is fundamentally tenant
  data. `client_id` doubles as the row's own `id` -- no reason to mint a
  second identifier for the same concept. `verify-secret` is enumeration-safe
  (identical response for "no such client" and "wrong secret"), same
  reasoning as `iam-identity-svc`'s `verify-password`. No pepper on the
  secret hash (unlike passwords) -- a client secret is already 256 bits of
  `SecureRandom` output, not a human-chosen low-entropy value, so peppering
  adds no real resistance here.
- **Login form is a deliberate stand-in, not a shortcut taken quietly:**
  `iam-login-portal` (Service 13) doesn't exist yet, so `/authorize` renders
  a minimal server-side HTML form itself. Documented in the contract and
  this entry specifically so it's replaced, not mistaken for the real thing,
  when Service 13 is built.
- **This is the actual fix for the real-IP problem, in the one place it can
  be fixed:** `POST /authorize/login`'s handler is the first genuine front
  door in the whole system -- the literal browser form submission -- so it
  extracts `request.remoteAddr` for real, unlike `iam-auth-svc`'s own
  `sourceIp` field (client-supplied there because nothing sits in front of
  it -- see the Service 7 entry). This was flagged as a known gap during
  Service 7 and is resolved here, not worked around.
- **Access tokens never contain the raw platform session token.** The
  temptation was to embed it directly in the JWT so `/userinfo` could
  re-validate the session without extra state -- rejected, because that
  would hand a third-party app a token capable of impersonating the user's
  session against every other platform service, not just answering
  `/userinfo`. Instead: a server-side Valkey link,
  `oidc:access:<sha256(access_token)> -> raw session token`, same
  never-store-the-raw-value pattern `iam-session-svc` already uses for its
  own keys. Confirmed live: `/userinfo` succeeds while the session is live,
  and returns `401` the instant the session is deleted -- proving the AP-2
  tie-in (a session `iam-enforcement-svc` kills mid-flight invalidates the
  OIDC access token immediately, not just at the token's own separate JWT
  expiry), not merely asserted.
- **Signing key (Tier-2, same deviation pattern as the password pepper and
  device-svc's TOTP DEK):** one platform-wide RSA-2048 keypair, get-or-create
  in OpenBao KV v2, not OpenBao Transit/PKI or true key rotation. BUILD_PLAN.md
  calls for "rotating JWKS" -- deferred; a real rotation needs a
  multi-key-with-overlap scheme this MVP doesn't build. Uses
  `com.nimbusds:nimbus-jose-jwt` for RSA/JWS/JWK handling (industry-standard,
  the same library Spring Security's own OAuth2 support is built on).
- **id_token vs access_token, standard OIDC split:** `id_token` is a
  one-time proof of authentication for the client app (`aud`=client_id,
  short TTL, never re-checked after issuance -- that's the spec).
  `access_token` is what backs `/userinfo` and is the one continuously
  tied to live session state, per the point above.
- **Authorization codes:** single-use, 60s TTL, Valkey `GETDEL` (same
  atomicity reasoning as `iam-session-svc`'s termination). A code is
  invalidated on *any* presentation to `/token`, success or failure --
  standard OAuth2 practice, prevents a leaked code being probed repeatedly
  against guesses at the client secret.
- **A retried `POST /authorize/login` -> `iam-auth-svc` call can't issue
  two sessions, without adding new idempotency plumbing:** `CorrelationIdFilter`
  already propagates an inbound `X-Correlation-Id` if present rather than
  always minting a fresh one, so a Resilience4j retry from this service
  (same header value both attempts, since it's the same thread/request)
  reaches `iam-auth-svc` with the same correlation ID both times, which
  `iam-auth-svc` in turn already uses as the `Idempotency-Key` for its own
  `iam-session-svc` call (Service 7 decision). The chain protects itself;
  confirmed by reading `CorrelationIdFilter`'s actual behavior rather than
  assuming it, and no code needed changing.
- **Bug found while verifying the TEST GATE -- Docker Desktop's daemon
  dropped mid-session (the same recurring instability seen throughout this
  project) and, on restart, recreated `openbao` fresh** (it runs in ephemeral
  dev mode with no persisted volume). This silently wiped the password
  pepper generated during Service 7's own testing, so a previously-working
  test user's password stopped verifying -- not a code bug, confirmed by
  testing the identical login directly against `iam-auth-svc` and seeing
  the same failure outside `iam-oidcprovider-svc` entirely. Fixed by
  resetting the affected test user's password so it re-hashes under the
  new pepper. No application change; logged so the failure mode is
  recognized immediately if it recurs.
- **Bug found -- local Docker-Compose testing cannot produce a real public
  source IP, so the just-fixed real-IP behavior above initially made every
  local OIDC login fail as "location could not be verified."** Requests
  hitting a host-mapped port arrive at the container from Docker's internal
  bridge gateway (a private RFC 1918 address, e.g. `172.19.0.1`), which no
  real GeoIP database has (or should have) an entry for -- this is the exact
  local-testing limitation already flagged as unavoidable during Service 7
  (see that entry: "even after all this is built correctly... testing will
  still need some way to simulate a different IP"). Fixed with a narrow,
  explicitly-labeled addition to `iam-geo-svc`: any RFC 1918 private address
  resolves to a fixed test country. This can never fire in a real deployment
  (a real ingress only ever sees real public client IPs), and does not
  touch resolution of any real IP -- confirmed live that `8.8.8.8` and the
  previously-used TEST-NET-3 fixture are both unaffected.

**TEST GATE (adapted from BUILD_PLAN.md's Grafana-shaped description --
no Grafana instance in this environment, so a `curl`-driven OIDC client
exercises the identical protocol surface any real client would use):**
registered a real OIDC client via `iam-tenant-svc`. `GET /authorize` with an
unknown `client_id`, and separately with an unregistered `redirect_uri`,
both return `400` directly -- never a redirect (verified: no `Location`
header on either). A valid request renders the login form. Submitting it
with the wrong password reproduces the same `401`->form-re-render path as a
direct `iam-auth-svc` call. Submitting it with a real password + a real,
freshly-generated TOTP code (RFC 6238, computed independently with
`openssl`/`base32`, not copied from the service) returns a `302` to the
registered `redirect_uri` carrying a single-use code. Exchanging it at
`/token` with the correct `client_secret` returns real, independently
decodable RS256-signed `id_token`/`access_token` JWTs; reusing the same
code, or presenting the wrong `client_secret`, both correctly fail with the
standard `invalid_grant`/`invalid_client` OAuth2 error shapes. `/userinfo`
returns the correct `sub`/`email`/`tenant_id` while the session is live, and
`401` the instant the underlying platform session is deleted -- confirmed by
reading the session-token link directly out of Valkey and deleting it via
`iam-session-svc`, simulating exactly what `iam-enforcement-svc` would do on
a real policy violation. All ten services now appear in Jaeger with linked
spans for the full chain, including the Redis/Kafka calls underneath it.
All verified against the real running ten-service stack, not mocked.

---

### Service 13 — iam-login-portal (interview, pre-implementation) (2026-09-17)

Spec written: `docs/specs/iam-login-portal-SPEC.md`. Interview surfaced
contract changes to two previously-built services, confirmed with product
owner before implementation (BUILD_PLAN.md working-agreement rule 3):

- **Handoff architecture:** iam-oidcprovider-svc's `GET /authorize` changes
  from rendering an inline HTML form to a `302` redirect to
  iam-login-portal; the placeholder `POST /authorize/login` is removed
  (nothing external ever called it) and replaced by a new
  `POST /authorize/complete` (session-token in, `{code, redirectUri}` out).
  Matches BUILD_PLAN.md's own diagram ("oidcprovider-svc redirects to
  iam-login-portal → login portal → iam-auth-svc") and is the first time
  iam-auth-svc's TOTP/push second factor becomes reachable from a real
  login instead of the placeholder form (which never sent `totpCode`).
- **Real-client-IP extraction** (the fix made in the Service 11 entry, on
  `POST /authorize/login`) moves to iam-login-portal, since that's now the
  actual front door receiving the literal browser connection.
- **iam-tenant-svc extended again** (same pattern as Service 11's OIDC
  client registration addition): new `GET
  /api/v1/tenants/by-subdomain/{subdomain}` so the portal can resolve
  `tenantId` from the Host header, per FR-6.2's subdomain-only login.
  Local Docker Compose has no wildcard DNS, so a documented dev-only
  `?tenant=` query-param override exists alongside the real path — same
  pattern as iam-geo-svc's private-IP fixture.
- **iam-auth-svc's `ErrorResponse` extended** with a required-on-403
  `errorCode` enum (`SECOND_FACTOR_REQUIRED | POLICY_DENIED | TOTP_INVALID
  | TOTP_LOCKED | PUSH_DENIED | PUSH_TIMEOUT`) so the portal can route to
  the correct screen without parsing the free-text `reason` field.
  Additive, existing callers unaffected.
- **Second-factor UX:** the portal shows both a TOTP code field and a
  "send a push" button up front rather than guessing which factor to try
  first, since iam-auth-svc's `/login` has no separate factor-selection
  endpoint and omitting `totpCode` triggers a real, up-to-60s blocking
  push wait.
- **FR-6.1 (per-tenant branding) explicitly deferred, not silently
  dropped:** no backend owns branding data yet (no admin console, no
  Tenant model fields for it). iam-login-portal ships one static generic
  theme for this SPEC; FR-6.1 stays open pending its own future SPEC.
- Scope for this SPEC is the OIDC login flow only — FR-2.14's self-service
  portal (password reset, MFA/device management) is a separate future
  module; no backend endpoints for it exist yet either.

`docs/OPEN_QUESTIONS.md` has no pending entries from this interview — both
Tier-3 items raised (2FA error-code contract change, branding deferral)
were resolved with the product owner during the interview itself, not left
open.

---

### Service 13 — iam-login-portal (implementation) (2026-09-17)

Built per `docs/specs/iam-login-portal-SPEC.md`. Backend contract changes
from the pre-implementation entry above were implemented in the same
session (same precedent as Service 11 extending `iam-tenant-svc`):

- `iam-tenant-svc`: `GET /api/v1/tenants/by-subdomain/{subdomain}` added.
- `iam-auth-svc`: `AuthErrorCode` enum + `LoginDeniedException.errorCode`
  added; every `LoginDeniedException` throw site now carries a specific
  code (`ACCOUNT_SUSPENDED`, `LOCATION_UNVERIFIED`, `POLICY_UNAVAILABLE`,
  `POLICY_DENIED`, `NO_SECOND_FACTOR_ENROLLED`, `NO_PUSH_DEVICE_ENROLLED`,
  `SECOND_FACTOR_UNAVAILABLE`, `TOTP_INVALID`, `TOTP_LOCKED`, `PUSH_DENIED`,
  `PUSH_TIMEOUT`) instead of the fixed list sketched during the interview --
  refined to match what `AuthService.login` actually throws, once written
  against the real code instead of the spec's sketch.
- `iam-service-kit`: `ErrorResponse` gained an optional `errorCode: String?`
  field (additive, defaults to `null`, existing `of(...)` call sites
  everywhere else unaffected).
- `iam-oidcprovider-svc`: `GET /authorize` redirects to iam-login-portal
  instead of rendering HTML; `POST /authorize/login` removed (dead code,
  nothing external ever called it); `POST /authorize/complete` added
  (session token in, `{code, redirectUri}` out via `AuthorizeCompleteResponse`).
  `AuthClient` (no longer called) deleted; `IdentityClient` added (resolves
  email for the id_token/access_token claims from the session's `userId`,
  since `/authorize/complete` only receives a session token, not an email
  the way the old form did). Also added a `CallNotPermittedException`/
  `ResourceAccessException` -> 503 handler to `GlobalExceptionHandler` --
  found missing while wiring `/authorize/complete`'s own 503 case; this
  service had no downstream-unavailable handler at all before.
- `iam-login-portal`: new Next.js repo (`C:\workspace\iam-login-portal`).
  Custom `server.js` (not `next start`) specifically to read
  `req.socket.remoteAddress` and inject it under an internal, client-
  unspoofable header before Next ever sees the request -- the real-IP fix
  moves here from `iam-oidcprovider-svc`'s old `POST /authorize/login`
  handler, since that's no longer the front door.

**Bugs found and fixed during the live TEST GATE (all local to this new
module, no further changes needed to any already-published service):**

- **A `"use server"` file can only export async functions.** `login/actions.ts`
  originally also exported `initialLoginFormState` (a plain object) for
  `useActionState`'s initial value. Every export of a `"use server"` file
  becomes a server-action reference, so a non-function export crashes the
  whole module at request time (`Error: A "use server" file can only export
  async functions, found object.`) -- found by actually submitting the
  form, not by the build (`next build` doesn't execute the action). Fixed
  by moving `LoginFormState`/`initialLoginFormState` into a separate
  `login/types.ts` with no `"use server"` directive.
- **Real IP arrives IPv6-mapped, not plain IPv4.** Node's dual-stack HTTP
  socket reports an IPv4 client as `::ffff:172.19.0.1`, not `172.19.0.1` --
  unlike the Java Servlet API (`HttpServletRequest.getRemoteAddr()`), which
  `iam-oidcprovider-svc`'s old `POST /authorize/login` handler relied on and
  which normalizes this automatically. Left un-normalized, `iam-geo-svc`
  correctly rejects it per its own IPv4-only contract
  (`contracts/iam-geo-svc.yaml`) with a `400`, which `iam-auth-svc`'s
  `orNull` soft-fail wrapper doesn't catch (it only catches unreachability,
  `CallNotPermittedException`/`ResourceAccessException`, not an unexpected
  4xx), so the whole login 500'd instead of degrading to "location could
  not be verified". Root-caused by adding temporary logging to
  `loginAction` and reproducing the exact failing call via `docker exec`
  directly against `iam-geo-svc`. **Fixed at the actual source of the bug**
  -- `server.js` strips a leading `::ffff:` prefix before setting the
  internal real-IP header -- rather than touching either already-published,
  already-tested service. `iam-auth-svc`'s `orNull` still only catches
  unreachability, not an unexpected 4xx from a soft-fail dependency; this is
  a latent, narrower gap than it looked like at first (a genuine, non-
  IPv4-mapped IPv6 client source address would still 500 the whole login
  in a real deployment) -- **flagged, not fixed**, since it's out of this
  module's scope to modify `iam-auth-svc`'s resilience behavior without
  asking first, and nothing in this MVP's scope produces a real IPv6 client
  address yet.
- **Docker Desktop's daemon dropped mid-session again** (the same recurring
  environment instability seen in every prior service's build) and, on
  restart, recreated `openbao` fresh (ephemeral dev mode, no persisted
  volume) -- wiped the password pepper and the device-svc TOTP encryption
  key again, same failure mode as the Service 11 entry. Not a code bug;
  fixture tenant/user/device/OIDC-client were recreated after the restart
  to continue testing. Postgres data survived (has a real volume); only
  OpenBao-derived secrets were lost.

**TEST GATE:** registered a real tenant, user (with password), TOTP device
(activated with an independently-computed RFC 6238 code, not copied from
the service), and OIDC client via direct API calls. `GET /authorize` against
`iam-oidcprovider-svc` returned a `302` to `iam-login-portal` with the
tenant's subdomain carried as a `?tenant=` dev-mode query param (no
wildcard DNS locally). Fetched the rendered login page from the real
running Next.js server and **submitted the actual React Server Action**
via its documented no-JS progressive-enhancement form-post fallback (not a
mocked call) -- a real password + a real, independently-generated TOTP
code produced a `303` redirect to the registered `redirect_uri` carrying a
single-use code; exchanging it at `/token` returned real, independently
decodable RS256-signed `id_token`/`access_token` JWTs; `/userinfo` returned
the correct `sub`/`email`/`tenant_id`. Reading the session-token link
directly out of Valkey and deleting the session via `iam-session-svc`
(simulating exactly what `iam-enforcement-svc` would do on a policy
violation) made the very next `/userinfo` call fail with `401` immediately
-- the AP-2 tie-in, re-confirmed through the new handoff, not just asserted
to still hold. A wrong password re-rendered the form with "Incorrect email
or password" (no redirect). A user with no push-capable device enrolled,
submitting the push path, was denied with "No push-capable device is
enrolled for this account" -- proving the `errorCode` -> UI-message mapping
works end-to-end through the real backend, not just the unit tests. An
unknown tenant redirected to the generic `/login/error` page, never a raw
500. All verified against the real ten-service-plus-portal stack, not
mocked.

**Not re-verified in this pass (flagged, not silently skipped):** the
push-approve *happy path* itself (blocking up to 60s, then a simulated
"approve" via `POST /api/v1/devices/push/respond`) wasn't re-exercised
through the new portal -- `iam-auth-svc`'s push-handling code is completely
unchanged by this module, and that exact mechanism was already
independently TEST-GATE-verified in the Service 9 entry. Re-running it here
would only be re-proving `iam-device-svc`/`iam-auth-svc` behavior this
module doesn't touch, not `iam-login-portal` itself.

---

### Service 14 — iam-admin-console (2026-09-18)

Built per `docs/specs/iam-admin-console-SPEC.md`. Interview surfaced a
bigger-than-usual gap before implementation started: **no admin/role
concept existed anywhere in the platform** -- `iam-identity-svc`'s `User`
model had no `role` field, and BUILD_PLAN.md's "two fixed roles" deviation
(D3) had never actually been implemented. Confirmed with product owner
before proceeding:

- **Real login + a role field**, not a shared static admin token.
- **Scope this pass:** tenants (view only, via existing endpoints -- no new
  list endpoint needed once scoped to "an admin manages only their own
  tenant"), OIDC clients (list + create), policy (view + edit). User
  management explicitly deferred.
- **Single-tenant scope only** -- no cross-tenant "platform super admin"
  view (BRD FR-7.2's Super Admin tier deferred).
- **`iam-policy-svc`'s `PUT /api/v1/policies` retrofitted with the new
  admin check**, not just left open -- this was previously the most
  consequential unauthenticated endpoint in the whole platform (anyone
  reaching the service could silently change any tenant's access policy).
  Confirmed explicitly with product owner as a second, separate question,
  since it's a real breaking change to a previously-built, tested
  endpoint's behavior (BUILD_PLAN.md working-agreement rule 3).

**What was built:**

- `iam-identity-svc`: `UserEntity.role` (`ADMIN`|`USER`, default `USER`,
  Flyway `V3__add_role.sql`), `CreateUserRequest.role` (optional),
  `VerifyPasswordResponse.role`, `UserResponse.role`, and a new
  `PATCH /api/v1/users/{id}/role` publishing `identity.role_changed`.
- `iam-auth-svc`: `LoginResponse.role`, read straight through from
  `iam-identity-svc`'s existing `verify-password` call (no new outbound
  call). UI-branching convenience only -- every admin-gated backend
  endpoint independently re-verifies role itself.
- `iam-tenant-svc` and `iam-policy-svc`: each gained its **own local**
  `SessionClient` + `IdentityClient` (their first outbound HTTP calls --
  `iam-policy-svc`'s own contract description said "no outbound calls" and
  had to be corrected) and an `AdminAccessGuard` -- validates
  `X-Session-Token` via `iam-session-svc`, confirms the session's
  `tenantId` matches the tenant being acted on, confirms the session's
  user resolves to `role=ADMIN` via `iam-identity-svc`. Deliberately **not**
  factored into `iam-service-kit`: this is authorization business logic,
  not technical infra, and BUILD_PLAN.md Section 4.5 explicitly restricts
  the shared kit to technical infra only -- same duplicate-per-service
  pattern every other cross-service client in this platform already
  follows.
  - `iam-tenant-svc`: new `GET /api/v1/oidc-clients?tenantId=` (admin-gated).
  - `iam-policy-svc`: new `GET /api/v1/policies?tenantId=&scope=&scopeId=`
    (admin-gated, fetches the raw stored record, not the merged/evaluated
    result); `PUT /api/v1/policies` retrofitted with the same guard.
- `iam-admin-console`: new repo, React + Vite SPA (`C:\workspace\iam-admin-console`).
  No server of its own -- session token lives in `sessionStorage`, every
  API call goes straight from the browser to `iam-auth-svc`/
  `iam-tenant-svc`/`iam-policy-svc`.

**Bugs/gaps found while wiring this up (all fixed except where noted):**

- **CORS was configured nowhere in the platform**, because nothing had
  ever needed it before -- `iam-login-portal`'s calls to backend services
  are server-side (Next.js Server Actions), never subject to the browser's
  same-origin policy. A pure SPA has no server to hide calls behind, so a
  real browser tab at `http://localhost:5173` calling `iam-auth-svc`/
  `iam-tenant-svc`/`iam-policy-svc` on different ports (different origins)
  would have been silently blocked -- invisible to `curl`-based testing,
  since CORS is a browser-only enforcement mechanism, not a server-side
  check. Found by reasoning about the actual browser request path, not by
  a failing test. Fixed: a small `CorsConfig` (`WebMvcConfigurer`) added to
  all three services, allowed origin configurable via
  `ADMIN_CONSOLE_ORIGIN` (default `http://localhost:5173`), no
  `allowCredentials` needed since the platform never uses cookies -- the
  session token travels only as an explicit header everywhere. Verified
  live with a real preflight `OPTIONS` request carrying
  `Origin: http://localhost:5173`, confirming the browser flow (not just
  the curl flow) will actually work.
- **A pure browser SPA cannot learn its own public IP.** Unlike
  `iam-login-portal`'s `server.js` (reads the real TCP socket
  server-side), there is no server here to do that from. Rather than
  introduce a second local-dev special case, `iam-admin-console` sends a
  fixed RFC 1918 address (`10.0.0.1`) as `sourceIp`, deliberately chosen to
  hit `iam-geo-svc`'s *existing* private-IP local-dev fixture (added back
  in Service 3). Labeled `MVP-TEMPORARY, LOCAL-DEV-ONLY` in code; would not
  work, and must not be relied on, against a real deployment.
- **The bootstrap `PATCH /users/{id}/role` endpoint has no auth at all.**
  Necessary -- the console can't promote the first admin before an admin
  exists to log into it -- but anyone who can reach `iam-identity-svc` can
  currently promote any user to `ADMIN`. Flagged, not fixed, matching the
  platform-wide D2 reality that no inter-service/caller authentication
  exists anywhere yet.
- **Docker Desktop's daemon dropped mid-session again** (the same
  recurring instability seen in Services 11 and 13), wiping OpenBao's
  ephemeral password pepper / TOTP DEK again. Test fixtures recreated
  after restart; no code bug.

**TEST GATE:** created a user (defaulted to `role: "USER"`, confirmed via
the API response), enrolled and activated a real TOTP device, logged in,
and confirmed the resulting session was correctly **denied** (`403 "admin
role required"`) on both the new `GET /oidc-clients` and the retrofitted
`PUT /policies` -- proving the guard actually blocks a non-admin, not just
that it exists. Promoted the same user to `ADMIN` via the bootstrap
endpoint, logged in again, and confirmed `LoginResponse.role` was now
`"ADMIN"` and every admin-gated call succeeded: policy `GET` correctly
`404`'d before anything was stored, `PUT` stored a real policy, a
subsequent `GET` returned exactly what was stored; an OIDC client was
registered and then appeared in the new list endpoint. Confirmed a request
with no `X-Session-Token` at all still fails clean (`400`), not a crash.
Verified CORS preflight succeeds for the exact origin/method/header
combinations the real SPA sends. Frontend itself: TypeScript build,
production Vite build, and unit tests (subdomain resolution, error-code
message mapping) all green; served correctly via `nginx` in the real
Docker stack. All verified against the real running stack, not mocked --
though, same honest caveat as Service 13, no literal browser click-through
was performed in this environment; every constituent piece (the served
SPA, every API call it makes, the CORS preflight for each) was verified
independently instead.

### D2 closure — OpenBao hardening + inter-service mTLS rollout (2026-09-19)

Closes MVP deviation D2 (`BUILD_PLAN.md` Section 3) and the "secrets
hardening" gap: OpenBao moved off `-dev` mode to a real, persistent
server (`infra/openbao/config.hcl`, raft integrated storage), and
service-to-service calls now authenticate via mutual TLS backed by
OpenBao's PKI secrets engine, not an open network with no auth at all.

- **Real OpenBao server mode.** `storage "raft" { path = "/openbao/file" }`
  -- deliberately reuses the image's pre-owned directory rather than a
  fresh Docker-created one, which came up root-owned and caused a
  permission-denied failure the first time. `disable_mlock` was dropped
  entirely (unrecognized field with `cap_add: IPC_LOCK` already granted).
  Consequence accepted as correct, not worked around: after any restart of
  the `openbao` container, OpenBao comes back up **sealed**, and every
  mTLS-dependent service's entrypoint will fail to authenticate until
  `infra/openbao/bootstrap.py` is re-run to unseal it. This is standard
  OpenBao/Vault security behavior (unseal keys are never stored alongside
  the data they protect) -- not a bug, and not worked around with an
  auto-unseal shortcut.
- **`bootstrap.py`** is the single idempotent entry point: init/unseal,
  generate the root CA (once) and a `internal-services` PKI role, mount a
  KV v2 engine, create an AppRole (`cert-issuer`) + policy, write
  `.env` (`BAO_APPROLE_ROLE_ID`/`BAO_APPROLE_SECRET_ID`) and a test-client
  cert. Bug found and fixed: an early version conflated "PKI mount exists"
  with "root CA already generated," so a partially-failed prior run would
  silently skip CA generation forever -- fixed by checking
  `GET /v1/pki/cert/ca` directly, and every OpenBao API call in the script
  now hard-fails (`sys.exit(1)`) on a non-2xx instead of continuing
  silently.
- **AppRole replaces the shared root token.** Every one of the 9
  mTLS-participating services now authenticates to OpenBao with its own
  AppRole login (`role_id` + `secret_id`) at container startup instead of
  a single root token baked into every container -- the literal thing D2
  flagged as unsafe ("any service can call any other/OpenBao with no
  real auth"). `iam-audit-svc` was left alone (no `BAO_TOKEN`/AppRole
  wiring) since it never reads OpenBao secrets.
- **PKI role + AppRole TTLs set to 720h (30 days), not a short-lived
  default.** Confirmed simplification, not an oversight: there is no
  renewal daemon in this MVP, and some KV-secret code paths only run on
  a rare event (e.g. TOTP DEK fetch), which could be well after container
  startup -- a short-lived token/cert would expire before ever being used
  once. A real production deployment would want short TTLs plus an
  actual renewal loop; flagged here, not built.
- **mTLS mesh scoped to actual caller graph, not blanket-applied --
  course-corrected mid-rollout.** The first pass put mandatory-or-optional
  mTLS on the inbound listener of all 9 services. Caught before finishing:
  5 of those 9 (`iam-tenant-svc`, `iam-policy-svc`, `iam-auth-svc`,
  `iam-enforcement-svc`, `iam-oidcprovider-svc`) are called directly by
  real browsers or `iam-login-portal`'s Node server, none of which can
  trust our self-signed internal CA. Reverted their inbound listener back
  to plain HTTP; they still fetch a client cert at startup (via the shared
  `mtls-entrypoint.sh`) so they can act as mTLS *clients* when calling the
  4 purely internal-only services (`iam-session-svc`, `iam-geo-svc`,
  `iam-identity-svc`, `iam-device-svc`), which now mandate
  `server.ssl.client-auth: need` on their own inbound listener. Those 4
  also split off a plain-HTTP `management.server.port` for
  actuator/health, since Spring Boot's `server.ssl.client-auth: need`
  would otherwise also demand a client cert from health-check callers
  that don't have one.
- **Mechanism:** `mtls-entrypoint.sh` (shared across all 9 Dockerfiles,
  lives at the workspace root, not inside any one service repo) does the
  AppRole login, requests a PKI cert for that service's CN, and builds a
  PKCS12 keystore/truststore via `openssl pkcs12 -export` + `keytool
  -importcert` -- deliberately no new PEM-parsing library dependency.
  Server-side TLS is Spring Boot's own `spring.ssl.bundle.jks.*`
  mechanism; client-side is a new `MtlsSslContext` singleton in
  `iam-service-kit` that `resilientRestClientBuilder` picks up
  automatically if `/mtls/*.p12` exists, a no-op otherwise. Bug found and
  fixed in the entrypoint script: `echo "$VAR" | jq` corrupted JSON
  containing PEM content, because dash's `echo` interprets backslash
  escapes and turned JSON-escaped `\n` into real newlines --
  fixed by switching every occurrence to `printf '%s' | jq`.
- **Verification:** confirmed the mesh survives a container restart
  (requires the manual `bootstrap.py` re-run above, by design); performed
  a real login flow and a full OIDC round trip end-to-end through the
  mTLS chain, plus re-confirmed the AP-2 session-kill path still works
  through it. Windows-native curl (Schannel) could not reliably present a
  client cert in this environment (exit 58, then exit 35 on PKCS12 retry)
  -- not an mTLS bug, confirmed by running the identical call from a
  Linux `curlimages/curl` container on the same Docker network instead,
  which worked; all subsequent mTLS testing used that method.
- **Not done, flagged for real deployment:** no cert renewal daemon (see
  TTL note above); no OpenBao auto-unseal (Shamir single-key-share
  unseal, matching local MVP simplicity, not a production KMS-backed
  auto-unseal).
- **`mtls-entrypoint.sh` lives in this repo at `infra/mtls-entrypoint.sh`,
  not inside any one service repo.** Every service's Dockerfile does
  `COPY mtls-entrypoint.sh /entrypoint.sh`, which resolves against
  `docker-compose.yml`'s build context (`../workspace`, the shared local
  checkout directory all 9 service repos + `iam-service-kit` sit
  alongside) -- it's genuinely shared infrastructure, not any one
  service's file, matching where `docker-compose.yml` itself already
  lives. **Local setup requirement:** copy this file to the workspace
  root (sibling of every service repo) before `docker compose build` --
  it is not picked up automatically from this repo's checkout location.

### D4a closure — multi-broker Kafka (2026-09-19)

Closes the Kafka-replication half of MVP deviation D4. Single-broker
Kafka replaced with a real 3-node KRaft cluster (`kafka-1`/`kafka-2`/
`kafka-3` in `docker-compose.yml`), each a combined broker+controller,
sharing one fixed `CLUSTER_ID` and `KAFKA_CONTROLLER_QUORUM_VOTERS` for
multi-node bootstrap. `audit-events` (and every other topic) now created
with replication factor 3; every producer across all 9 producing
services sets `acks: all` so a write isn't considered durable until it
reaches the in-sync replica set, not just the leader.

- YAML anchors (`&kafka-common`, `<<: *kafka-common-env`) were tried
  first to avoid repeating the 3 near-identical broker blocks, but merge
  keys collided with an already-present `environment:` key in the same
  service mapping ("duplicate key"). Abandoned in favor of three full,
  explicit, non-anchored service blocks -- more verbose, but no merge-key
  fragility.
- Two transient Docker networking issues during rollout, neither a
  configuration bug: an orphaned container from the old single-broker
  service (`iam_core_platform-kafka-1`, a naming coincidence with the new
  `kafka-1` service) was still bound to host port 9092 and had to be
  removed before the new named services could start; separately, one
  broker came up with no network attached on first boot
  (`NetworkSettings.Networks: {}`), which a plain `docker restart` didn't
  fix -- required a full `docker rm -f` + `docker compose up -d` recreate.
- **Verified:** real 3-broker quorum forms; `audit-events` confirmed at
  replication factor 3 via the actual topic description; the full
  producer -> replicated topic -> consumer -> Postgres pipeline re-tested
  end-to-end afterward.

### D4b — Postgres redundancy documented, not simulated locally (2026-09-19)

The other half of D4 (single Postgres host, no redundancy) is
deliberately **not** faked in docker-compose. CloudNativePG is a
Kubernetes operator (it manages failover via a Kubernetes-native
controller, PodDisruptionBudgets, etc.) -- there is no meaningful way to
run "a CloudNativePG cluster" under plain Docker Compose; simulating
redundancy with, say, two independent plain-Postgres containers and a
hand-rolled replication script would prove nothing about the actual
target technology and would be thrown away at real deployment time
anyway. Confirmed with the product owner: document the deployment-time
shape instead of building a fake stand-in locally.

- **`infra/postgres/cloudnativepg-cluster.yaml`** -- a prepared (not yet
  applied) Kubernetes manifest for a 3-instance CloudNativePG `Cluster`
  per BUILD_PLAN.md's per-service-database topology, meant to be applied
  once a real GKE cluster + the CloudNativePG operator exist. Not
  runnable today; exists so the deployment step has a concrete starting
  point instead of a blank page.

### Gateway rollout — `iam-enforcement-svc` as a real reverse proxy (2026-09-19)

Closes the "no real gateway/reverse-proxy wiring in front of protected
apps" gap. Until now, continuous enforcement (AP-2) was only ever proven
by calling `POST /api/v1/enforce` directly -- never against real
forwarded application traffic, which is the actual "PEP fronting a
protected app" shape the architecture describes.

- **`ProxyController`** in `iam-enforcement-svc`, mapped on the `/proxy`
  path prefix: forwards every method/path/query/body/header (except
  `Host` and `X-Session-Token`, both deliberately stripped) to a
  config-driven `iam.enforcement.proxy.upstream-url`, after running the
  exact same session+location+policy check `POST /api/v1/enforce`
  already does. A denied request never reaches the upstream. Built as a
  hand-rolled servlet-based proxy (`HttpServletRequest`/
  `HttpServletResponse` + `RestClient`), not Spring Cloud Gateway --
  confirmed as the right call, since Cloud Gateway is WebFlux-based and
  would be a bigger paradigm shift than this MVP piece warrants, and
  this service already reuses `iam-service-kit`'s existing
  `resilientRestClientBuilder` for the same bounded-timeout guarantee
  every other outbound call in the platform has.
- **Proven against `traefik/whoami`, not a placeholder assertion:** a
  lightweight stand-in "protected app" added to `docker-compose.yml`
  purely to give the proxy something real to forward to and echo back.
  Verified all three cases end-to-end: no `X-Session-Token` -> `401`
  before any upstream call; an invalid/unresolvable token -> `401` via
  the same `EnforcementDeniedException` path `/api/v1/enforce` uses; a
  real, live session token -> request actually reaches `whoami` and its
  echoed response (method, path, query, headers) is returned unchanged,
  confirming the session token itself never leaks to the upstream.
  Re-verified `POST /api/v1/enforce` itself still works unchanged
  alongside the new controller.
- Two Kotlin compile bugs found and fixed while writing this: a KDoc
  comment containing the literal text `/proxy/**` broke compilation,
  because Kotlin block comments nest (unlike C/Java) so a `/*`-shaped
  substring mid-comment opens an unmatched nested comment -- reworded to
  avoid the literal pattern. `HttpHeaders.forEach { (name, values) -> }`
  also failed to compile -- it resolves to Java's two-argument
  `Map.forEach(BiConsumer)`, not Kotlin's single-destructured-param
  `Iterable<Map.Entry>.forEach` -- rewritten as a two-parameter lambda.
- **Deliberately not built, flagged for real deployment (at the time):**
  session token travels as `X-Session-Token`, matching this platform's
  convention everywhere else -- not a cookie. A real deployment fronting a
  cookie-session'd app (a deployed Pulse, for example) would need a
  translation step (issue/read a cookie, map it to a session token) that
  this MVP gateway does not build. Also not built: TLS termination in
  front of the gateway itself, and routing based on hostname/path to
  more than one upstream (`upstream-url` is a single fixed target). **The
  cookie translation step was built next -- see the following entry.**

### Gateway cookie-login — the gateway as its own OpenID Connect client (2026-09-20)

Closes the cookie-translation gap flagged above. `iam-enforcement-svc`'s
gateway can now authenticate a plain browser that holds neither an
`X-Session-Token` header nor a cookie, by acting as its own OpenID Connect
Relying Party -- the same role a real third-party app (Grafana, or a real
deployed Pulse) plays today. This is the actual missing piece for putting a
real cookie-based app behind this gateway.

- **Flow:** an unauthenticated request to any `/proxy/**` path redirects
  the browser to the OpenID Connect Provider Service's existing
  `GET /authorize` (registered exactly like any other third-party client,
  via `iam-tenant-svc`'s `POST /api/v1/oidc-clients` -- no new
  registration mechanism). The existing, completely unmodified
  Login Portal flow runs (password + second factor). On success, the
  browser lands on a new `GET /oauth2/callback` on the gateway itself,
  which exchanges the authorization code via the OIDC Provider Service's
  existing `POST /token` (also unmodified), then sets an `HttpOnly`,
  `SameSite=Lax` cookie containing the OpenID Connect access token, and
  redirects to the originally requested `/proxy/...` path (round-tripped
  through the `state` parameter, base64-encoded, restricted on the way
  back to paths starting with `/proxy` -- an open-redirect guard, since
  `state` is browser-controlled). Every subsequent request presents that
  cookie; the gateway calls the existing `GET /userinfo` to confirm
  liveness and identity, then runs the same geo/policy re-check
  `EnforcementService.enforce` already does (new method
  `checkLocationAndPolicy`, added alongside the original, unmodified
  `enforce` -- same 30s policy cache, same never-fail-open behavior, same
  terminate-vs-just-deny distinction).
- **The raw platform session token is still never handed to the gateway**,
  preserving `AccessTokenLinkStore`'s existing third-party protection
  (documented at Service 11) -- confirmed as the right call rather than
  weakening that boundary for convenience. Instead, one small, genuinely
  internal-only addition to `iam-oidcprovider-svc`:
  `POST /internal/access-tokens/terminate`, which resolves an access token
  to its underlying session token server-side (via the existing
  `AccessTokenLinkStore`) and terminates it, without ever returning the
  raw token to the caller. Only the gateway calls this, only on an actual
  policy violation (`GatewayCheckResult.shouldTerminate`) -- an unresolved
  location or an unreachable policy service still denies the one request
  without touching the underlying session, same precedent as the original
  `enforce`.
- **Cookie built by hand (`Set-Cookie` header string), not
  `jakarta.servlet.http.Cookie`** -- the Servlet API's `Cookie` class has
  no `SameSite` attribute, and `SameSite=Lax` matters here (the browser
  needs to actually send the cookie back after the top-level-navigation
  redirect chain from the OIDC Provider Service).
- **Real bug found during verification, not just during writing:** the
  new `oidc-provider` Resilience4j instance's circuit-breaker/retry config
  didn't exclude a `401` from `GET /userinfo` (an expired/already-
  terminated access token -- a legitimate, expected business outcome, not
  a failure) from being retried and counted as a circuit-breaker failure,
  unlike every other client's config, which explicitly excludes its own
  expected 4xx (e.g. `session-svc`'s retry/circuit-breaker excluding
  `HttpClientErrorException$NotFound`). Five rapid retries against a
  legitimate 401 tripped the circuit breaker mid-request, and the
  resulting `CallNotPermittedException` wasn't caught by
  `GatewayOidcClient.userInfo`'s `catch (ex: HttpClientErrorException)` --
  it surfaced as an uncaught 503 with a misleading hardcoded message
  ("iam-session-svc is currently unavailable", from
  `GlobalExceptionHandler`'s catch-all, unrelated to which downstream
  actually failed). Fixed by adding
  `HttpClientErrorException$Unauthorized` to both the circuit-breaker's
  and retry's `ignore-exceptions` for the `oidc-provider` instance, same
  pattern as the pre-existing services.
- **Verified end-to-end, including the negative paths:** no cookie/no
  header -> redirects to `/authorize` with the correct client id and a
  correctly base64-encoded `state`; a real login (via the same
  server-side `POST /authorize/complete` call the Login Portal itself
  makes) followed by hitting the gateway's own `/oauth2/callback` ->
  cookie set, redirected to the original `/proxy/` path; the cookie then
  successfully forwards to `whoami` with the session cookie stripped from
  what the upstream sees; manually terminating the session (simulating an
  enforcement-triggered kill) and retrying with the now-dead cookie ->
  cookie cleared, redirected back to `/authorize` again, not a crash or a
  silent pass-through; `/oauth2/logout` with no cookie at all is a safe
  no-op, not an error; the pre-existing `X-Session-Token` header path and
  the direct `POST /api/v1/enforce` endpoint were both re-verified
  unchanged afterward.
- **Deliberately not built:** the upstream app's own cookies are never
  forwarded at all when the caller authenticated via the gateway's cookie
  (the whole `Cookie` header is stripped, not just this gateway's own
  cookie) -- fine for `whoami` (cookie-less), but a real app that sets its
  own cookies would need finer-grained cookie splitting this MVP doesn't
  build. Also not built: cookie/token refresh before expiry (the cookie's
  `Max-Age` matches the OpenID Connect access token's own TTL; once it
  expires, the next request simply redirects through login again, which
  is correct but not seamless).

### Gateway identity headers -- trusted user identity forwarded to the upstream app (2026-09-20)

Answers the question raised while writing up the real Pulse-integration
setup steps: the gateway forwarded traffic to the upstream app, but never
told the app *who* was making the request -- fine for an app that doesn't
need per-user awareness, not fine for anything that does. Confirmed with
the product owner ("standard practice") that a real third-party app should
be able to trust an asserted identity from the gateway rather than doing
any login work itself.

- Every request that passes enforcement -- through **either** auth path
  (the original `X-Session-Token` header, or the newer gateway cookie) --
  now gets three headers added before forwarding: `X-Auth-User-Id`,
  `X-Auth-Tenant-Id`, and (cookie path only) `X-Auth-User-Email`. New
  `GatewayIdentity` data class in `ProxyController.kt` carries this
  through both branches of the existing `when` in `proxy()` to the shared
  `forwardToUpstream`, rather than duplicating the header-building logic
  per auth path.
- **Email is only available on the cookie path, not the header path** --
  the header path's `enforce()`/`EnforceResponse` never carried an email
  (no `IdentityClient` exists in this service; the cookie path gets it for
  free from the OpenID Connect Provider Service's `/userinfo`, already
  called for liveness). Adding an `IdentityClient` purely for this one
  field was judged out of scope for now -- flagged, not silently done, in
  case a caller depends on `X-Auth-User-Email` always being present.
- **Anti-spoofing, not just addition:** any incoming `X-Auth-*` header is
  stripped before the gateway's own values are set, exactly like the
  existing `X-Session-Token` treatment -- otherwise a caller could simply
  set `X-Auth-User-Id: <victim>` on their own request and impersonate
  anyone, defeating the entire point of the header being "trusted."
  Verified directly: a request carrying forged `X-Auth-User-Id` and
  `X-Auth-User-Email` headers reached `whoami` with only the gateway's own
  real values present, the forged ones gone entirely.
- **Verified for both auth paths** against `whoami`'s header echo: the
  `X-Session-Token` path shows the two available fields (no email); the
  cookie path shows all three.

---

- **[repo structure] 2026-10-26** — Switched from polyrepo to monorepo:
  all 13 service repos (`iam-tenant-svc`, `iam-identity-svc`, `iam-auth-svc`,
  `iam-policy-svc`, `iam-session-svc`, `iam-device-svc`, `iam-geo-svc`,
  `iam-enforcement-svc`, `iam-oidcprovider-svc`, `iam-audit-svc`,
  `iam-service-kit`, `iam-admin-console`, `iam-login-portal`) plus
  `service-template` moved from a separate `C:\workspace\` into this repo's
  `services/` folder. Reason: a single developer builds every service here,
  and the polyrepo's actual day-to-day cost (one feature routinely spans
  3-5 services, each needing its own clone/commit/PR) was outweighing its
  benefit (team-boundary isolation, independent release cadence) — benefits
  that mainly matter with multiple teams, which this project doesn't have.
  Purely a source-control change: `docker-compose.yml`'s build `context`
  moved from `../workspace` to `./services`, each service's Dockerfile
  still only `COPY`s its own subfolder, so nothing about how services build
  or deploy changed. Applied to both the local machine and the GCE demo VM
  (`/opt/iam/workspace` + `/opt/iam/Iam_core_Platform` consolidated the same
  way). Each service's own git history was set aside on disk
  (`services/<name>/.git.old-history-backup/`, gitignored) rather than
  merged in or deleted — a fresh single history starts from this commit.
  AP-5 (on-prem portability / a service shipping independently later) is
  unaffected: a folder can still be pulled back out into its own repo
  whenever that's actually needed; nothing about the monorepo precludes it.

---

- **[infra] 2026-10-26** — Migrated the demo deployment's primary datastore
  from self-hosted Postgres (a container on the VM) to Cloud SQL
  (`db-f1-micro`, `ENTERPRISE` edition). An **explicit override** of this
  project's own earlier "self-hosted Postgres, NOT Cloud SQL" decision
  (AP-5 portability reasoning) — confirmed directly with the product owner
  before proceeding, logged here rather than silently changed. Scoped to
  this single-VM demo only; the real GKE/CloudNativePG target
  (`infra/postgres/cloudnativepg-cluster.yaml`) is unaffected and remains
  the AP-5-compliant path for an actual production/on-prem rollout.
  Provisioned via OpenTofu (`infra/opentofu/`), the project's first
  infra-as-code, rather than one-off `gcloud` commands.
  - **Connection method**: Cloud SQL Auth Proxy (`cloudsql-proxy` service
    in docker-compose), not a public IP + authorized-networks. The proxy
    authenticates via the VM's own service account (granted
    `roles/cloudsql.client`) through the Cloud SQL Admin API — no open
    port, no password-based network exposure. Two real gotchas hit live
    during setup: (1) the VM's *instance-level* OAuth scopes (separate
    from IAM role grants) didn't include `sqlservice.admin`, requiring a
    VM stop/start to update — IAM permissions and instance scopes are
    independently enforced on GCE, both have to allow a given API call.
    (2) The proxy's official image is distroless (no `nc`/`curl`/`wget`),
    so a `CMD`-based Docker healthcheck can never succeed against it —
    removed the healthcheck entirely; dependents use
    `condition: service_started` instead (the proxy is reliably listening
    within ~1s of starting, confirmed in its own logs).
  - **Tier note**: `db-f1-micro`'s low `max_connections` ceiling was
    exceeded by 5 services' default-sized (10) HikariCP pools starting
    concurrently — two services crash-looped on "remaining connection
    slots are reserved" until each service's `spring.datasource.hikari.
    maximum-pool-size` was capped at 3 (`DB_POOL_SIZE` env var,
    overridable). Worth revisiting if this tier is ever kept beyond demo
    use or more services are added.
  - **Password**: generated by OpenTofu (`random_password`), stored only
    in OpenTofu state (gitignored, never committed) and the VM's `.env`
    (`DB_PASSWORD`) — same "never in source, never logged" pattern as
    every other credential in this system.
  - **Migration**: `pg_dump | psql` piped directly from the old
    self-hosted container through the Auth Proxy into Cloud SQL, per
    database (`tenant_db`, `identity_db`, `policy_db`, `device_db`,
    `audit_db`). Row counts verified to match exactly before cutting any
    service over. The old self-hosted `postgres` container and its volume
    were deliberately left running (unused, not deleted) as a rollback
    safety net — not yet decommissioned.
  - **Viewing data**: Cloud SQL Studio (built into the GCP Console, zero
    setup) is now the primary way to browse data, replacing the briefly
    -opened public port 5432 on the self-hosted container (closed again
    once this migration completed).

---

- **[iam-admin-console] 2026-10-26** — Fixed `resolveTenantSubdomain` to
  check the explicit `?tenant=` override before the Host header, not
  after. Found live: restoring `ADMIN_CONSOLE_ROOT_DOMAIN` to its real
  value (same session, same day, see the entry above on CORS/env-var
  restoration) exposed a dormant bug -- `admin.34-71-129-0.sslip.io`
  parsed as if "admin" were itself a tenant subdomain, silently ignoring
  `?tenant=econz` entirely. This console is always one fixed shared
  hostname for every tenant, never a true per-tenant subdomain, so the
  override must always win here -- unlike `iam-login-portal`'s own
  (separate, intentionally different) copy of this function, where
  Host-header-first is correct by design for real per-tenant DNS
  subdomains in production.
  **Dormant risk, not yet fixed**: `iam-login-portal` has the identical
  code shape, currently harmless only because `LOGIN_PORTAL_ROOT_DOMAIN`
  is still unset (`platform.example.com` placeholder). If it's ever set
  to this demo's real shared root domain (`34-71-129-0.sslip.io`) while
  `iam-login-portal` still uses a single fixed `login.` hostname rather
  than true per-tenant DNS, the same failure will resurface there too --
  check this before setting that variable.

---

- **[iam-session-svc / iam-tenant-svc / iam-admin-console] 2026-10-27** --
  Added active-session management. New Valkey set per user
  (`user-sessions:<tenantId>:<userId>`, members are token *hashes*, never raw
  tokens), maintained on issue and terminate, with its TTL refreshed on every
  issue. New internal endpoints in iam-session-svc to list, end one, or end all
  of a user's sessions (`/api/v1/sessions/by-user/...`), proxied by
  iam-tenant-svc for admins (`/api/v1/admin/users/{id}/sessions`, target user
  re-resolved and tenant-checked, `session.revoked_by_admin` audit event with
  the admin as actor) and for users on themselves (`/api/v1/me/sessions`,
  including "sign out of all other devices"). Ending a session deletes it, so
  iam-enforcement-svc rejects the next request using it (AP-2). Sessions issued
  before this change are not in the index and so are not listed; they expire
  on their own within the session TTL. Traceability: FR-11.1 (session
  lifecycle) and AP-2 (killable mid-flight); there is no FR that names
  "list/revoke sessions" explicitly -- flagged as OQ-8.

- **[iam-tenant-svc / iam-login-portal / iam-admin-console] 2026-10-27** --
  Added per-tenant branding (FR-6.1): new `tenant_branding` table (one
  optional row per tenant: `#RRGGBB` color, https logo URL, headline, default
  theme), returned inside the existing public tenant lookups
  (`/tenants/by-subdomain/{s}`, `/tenants/{id}`) so a branded page costs no
  extra round trip, written via admin-only `PUT /api/v1/admin/branding`
  (`tenant.branding_updated` audit event). The color is validated server-side
  *and* re-validated where it is injected into CSS custom properties (login
  portal `brandStyle`), and the logo must be `https://`; both are guards
  against CSS/URL injection on a pre-login page. Logo is a URL only, no upload
  (see OQ-7).

- **[iam-policy-svc / iam-identity-svc / iam-auth-svc / iam-tenant-svc]
  2026-10-27** -- Added tenant password rules (FR-3.1) and account lockout
  (FR-3.5), kept inside the single engine (AP-1): the settings are new nullable
  columns on the TENANT-scope policy row (rejected on OU/USER scope, range
  checked), exposed as effective-with-defaults values at
  `GET /api/v1/security-settings`, and enforced where credentials live, in
  iam-identity-svc. Complexity is checked on create and set-password and fails
  closed (503) if the rules cannot be read. Lockout state
  (`failed_login_attempts`, `locked_until`, `permanently_locked`) lives on the
  user row; the counter is incremented atomically in SQL; a correct password
  clears it; locked-account guesses are not counted, so an attacker cannot
  extend a lock. If iam-policy-svc is unreachable while recording a failure,
  the failure is still counted and the lock engages on the next failure once
  settings are readable (an outage must neither lock everyone out nor lose
  counts). Admins unlock from the Users page
  (`identity.unlocked_by_admin` audit, admin as actor). Defaults: lockout OFF,
  min length 8, no character-class rules (OQ-4). The tenant service now
  ignores HTTP 400 from iam-identity-svc in its retry and circuit-breaker
  config, so a weak password is reported once, not retried five times and
  counted toward opening the breaker.
  Not changed: password hashing (Argon2id parameters untouched), the device
  service's own TOTP lockout (still 5 attempts / 5 minutes, not configurable).

- **[iam-admin-console] 2026-10-27** -- UI layer: toast notifications and a
  confirm dialog replace `window.confirm`; one `useTable` hook gives every
  list client-side search, sort and pagination (lists are fully loaded and
  small, the hook's return shape is the seam for server-side paging later);
  Policy page now loads and re-sends every tenant-scope policy field, because
  the old page PUT only a subset and `PUT /policies` overwrites the whole row,
  so saving it silently wiped the tenant IP ranges and 2FA setting.
  Also fixed two stale tests found while running the suites for the first time
  in this area: `OidcClientServiceTest` no longer compiled after group-based
  app access added a constructor parameter (which blocked every iam-tenant-svc
  test), and `SessionServiceTest` assumed an 8h TTL while
  `SessionProperties` defaults to 1h.

---

- **[iam-admin-console] 2026-10-27** -- Hardened the "session token lives in
  sessionStorage" risk (the SPA has no server to hold an httpOnly cookie)
  without changing where the token is stored. (1) nginx now sends a strict
  Content-Security-Policy: `script-src 'self'` (no inline or injected script
  runs), `connect-src` limited to this deployment's own backend origins, plus
  `frame-ancestors 'none'`, `base-uri 'self'`, `object-src 'none'`,
  X-Frame-Options, nosniff, Referrer-Policy and Permissions-Policy. The allowed
  origins come from the container's environment via nginx's envsubst templates
  (`CSP_CONNECT_SRC`, set in docker-compose.yml from the same
  ADMIN_CONSOLE_*_URL values as the build args), so one image serves any
  hostnames. The inline theme script moved to `/theme-init.js` to satisfy
  `script-src`. (2) The console signs a person out after 30 minutes without
  activity in the tab (server session ended too). (3) The last organization
  signed in to is remembered as a non-secret hint, so the sign-in page still
  works after a sign-out. Deliberately no `form-action` rule: the My Apps tiles
  POST to the login portal, which redirects on to the app, and browsers apply
  form-action to that redirect. Verification: the built bundle was checked
  statically (no inline scripts, no XHR/WebSocket, no CSS url(), every external
  host is an image CDN or display text); it was NOT run in a real browser, since
  pulling a third-party headless-browser image onto the server was declined.
  Smoke-test the console in Chrome and watch the DevTools console for
  "Refused to ..." messages. The root fix (httpOnly cookie) is OQ-10.

---

- **[iam-tenant-svc / iam-oidcprovider-svc / iam-login-portal / iam-admin-console]
  2026-10-27** -- User lifecycle propagation, SCIM provisioning and app-access
  enforcement (FR-2.7, FR-2.8). (1) **Suspend / reactivate**: admin endpoints in
  iam-tenant-svc set the status in iam-identity-svc, end every live session at
  once (a suspended user is signed out now, not at expiry), then push the change
  downstream; an admin cannot suspend themself. Audited as
  `identity.suspended_by_admin` / `identity.reactivated_by_admin`. (2) **SCIM 2.0
  outbound provisioning** (platform -> app): per-app `scim_connections` (URL +
  bearer token; the token lives in OpenBao at `scim/<id>`, never in Postgres) and
  `provisioned_accounts` (the app's own resource id per user, so a later
  suspend/delete addresses exactly the account we created). Create = POST /Users
  (a 409 "already exists" is linked to the existing account, found by userName
  filter), suspend/reactivate = PATCH `active` (GET+PUT fallback for servers
  without PATCH), delete = DELETE /Users/{id}. Reconciliation is state-based and
  idempotent, so "Retry" is always safe; failures never undo the platform-side
  change, are stored per user and app (`last_error`), audited
  (`provisioning.failed`), and shown to the admin. Only accounts we created or
  adopted are ever suspended or deleted. Google Workspace is suspended and
  reactivated through the Directory API; addresses outside the configured Google
  domain are skipped (Google answers 403 for them). Hand-rolled client, no SCIM
  library or new dependency. (3) **SSRF guard** (`OutboundUrlGuard`): an admin
  supplies the SCIM URL and the server calls it, so https only, no credentials in
  the URL, and every resolved address must be public (no loopback, private,
  link-local incl. 169.254.169.254, CGNAT, unique-local); checked when saving AND
  on every call, redirects are never followed, 5s connect / 10s read timeouts.
  `iam.provisioning.allow-private-targets` (env `SCIM_ALLOW_PRIVATE_TARGETS`,
  default false) lifts this for local development only. Residual risk: DNS
  rebinding between check and connect. (4) **Group enforcement at sign-in**:
  iam-oidcprovider-svc asks iam-tenant-svc `GET /api/v1/app-access` (authenticated
  by the user's own session token, so it only describes the caller) before
  issuing an OIDC code or signing a SAML assertion; same rule as the launchpad
  (admins: any app of their tenant; others: only apps assigned to their group; no
  group or no assigned groups means no access). Denied sign-ins return 403
  `APP_ACCESS_DENIED`, are audited (`oidc.access_denied` / `saml.access_denied`)
  and the login portal shows a clear message. Fails closed. Behavior change:
  groups were previously only a launchpad filter.
  Tested live: group enforcement, suspend/reactivate (status, sessions, sign-in
  block, audit), address-safety refusals. NOT yet tested live: an end-to-end SCIM
  push, because storing a connection's token needs `secret/data/scim/*` added to
  the `cert-issuer` OpenBao policy (done in `infra/openbao/bootstrap.py`, not yet
  applied on the server; see OQ-11).
- **2026-10-29 -- Sign-in context is captured on the server: real IP, browser/OS, country, region, city (Tier 2,
  user-approved; replaces the "MVP-TEMPORARY: client-supplied sourceIp" decision from Service 7).**
  (1) **IP.** `iam-auth-svc` no longer trusts the `sourceIp` in the login body. `ClientContext` takes the
  last hop of `X-Forwarded-For` (Caddy overwrites whatever the client sent with the address it saw); only when
  that header is absent -- a trusted internal caller such as iam-login-portal, which derives the IP itself in
  server.js -- does it use the body value, then the socket address. The body field stays optional for
  compatibility. (2) **Browser/OS.** The User-Agent (forwarded by the portal, read from the header for direct
  browser callers) is stored on the session. (3) **Location.** `iam-geo-svc` now loads DB-IP "IP to City
  Lite" (CC BY 4.0, attribution required; ~130 MB so downloaded at image build time, not committed; falls
  back to the bundled country-only file if absent) and returns region and city; auth-svc stores country,
  region and city on the session, session-svc/tenant-svc pass them through, the admin Sessions dialog and My
  Security show Location and Device, and the `auth.login_success` / `session.issued` audit reasons carry them.
  Old sessions show "Not recorded". City accuracy from a free database is approximate (often the nearest big
  city or the ISP hub); VPN or mobile-carrier addresses show the exit point, not the person.
  **Residual risk, needs an infrastructure change:** the VM firewall rule `allow-iam-platform-demo` exposes the
  raw service ports (8082 tenant, 8085 policy, 8087 auth, 8089, 8090, 5173, 3001, 3002) to 0.0.0.0/0, so a caller
  that skips Caddy and hits e.g. http://<vm-ip>:8087 directly can still send any X-Forwarded-For or sourceIp.
  Until those ports are closed (only 80/443 should be public; Caddy reaches the services on localhost) the
  server-side IP is only as trustworthy as that network boundary.
- **2026-11-16 -- Endpoint Device Trust, Phase 1 (Windows): decisions recorded after the fact.** Built
  2026-11-09..11-10 from the PDF "IAM Endpoint Device Trust Technical Specification v1"; the interview/SPEC
  step and this log were skipped (process miss, see OPEN_QUESTIONS OQ-16..OQ-25). Recorded now so a reviewer
  does not have to reverse-engineer them from the diff.
  **Tier 2 (within scope, no security-semantics change):** new additive tables in `V9`/`V10` (`iam_devices`,
  `iam_device_hardware/keys/certificates/approvals/posture/heartbeats/events/policies/app_policies`,
  `iam_device_enrollment_transactions`, `iam_agent_releases`; nothing existing was altered); new
  `/api/v1/endpoint/*` endpoints in `iam-tenant-svc`; `/internal/devices/{id}` for the PEP; the admin
  "Endpoint Security" page; `OpenBaoPkiClient` / `OpenBaoTransitClient` in `iam-service-kit`; Rust crates
  `tokio`, `reqwest` (rustls), `serde`, `uuid`, `tracing`, `thiserror`, `anyhow` (all named in PDF 7.3), plus
  `ed25519-dalek`, `sha2`, `base64`, `rand`, `chrono`, `windows-service` (not named in the PDF).
  **Tier 3, made provisionally and NOT yet confirmed by a human (do not treat as approved):**
  (1) device keys are software Ed25519 (X.509 SPKI DER on the wire), private key persisted in plaintext JSON
  -- violates FR-5.2/NFR-5.1 on TPM hardware (OQ-17); (2) enrollment is key-bound, PKCE-style: the agent sends
  base64url(SHA-256(SPKI DER)) before sign-in and only that key can finish the transaction (OQ-19); (3) the
  agent never holds a session token: `iam-login-portal` `/device-enroll` calls `enrollment/start` server-side
  and redirects to a validated `127.0.0.1`/`[::1]` loopback URL (RFC 8252); (4) device policy responses are
  signed by OpenBao transit key `device-policy` over a custom canonical string that the agent re-derives
  (OQ-23); (5) device-authenticated calls use `X-Device-Signature`/`X-Device-Timestamp` with a 120s window
  instead of mTLS (OQ-23); (6) defaults: corporate devices auto-approve, BYOD is manual, max 5 devices per
  user, certificate TTL 90 days, enrollment transaction TTL 5 minutes (PDF D03/D11); (7) the PEP terminates a
  session whose *claimed* device is not `APPROVED` -- a hardcoded rule, not a merged policy (OQ-20, AP-4).
  **Bugs found and fixed while building:** a failed enrollment attempt did not burn its transaction because the
  surrounding `@Transactional` rolled the `consumed_at` write back (now `noRollbackFor`); the first
  `iam-enforcement-svc` Docker build silently failed (parallel Gradle cache lock) and left the old image
  running while the pipeline reported success -- builds are now run with `pipefail` and verified by image age.
  Also fixed `EnforcementServiceTest`, which had not compiled against the real constructor since the identity
  check was added. **Not verified:** all Windows-only agent code (`platform/windows.rs`) had never been compiled
  or run on Windows as of this entry.
- **2026-11-16 -- Endpoint agent: owner directive, Phase B1 (policy lifecycle) and B2 (Windows executable).**
  **Owner directive:** the product owner told the team to follow the PDF "IAM Endpoint Device Trust Technical
  Specification v1" for the agent (resolves the *which document governs* part of OQ-16 in the PDF's favour). The BRD-only
  requirements the PDF omits (GPS FR-5.5, remote-authorized uninstall FR-5.10..5.13, native Chromium policy FR-5.7) are
  therefore **not built and not scheduled**; they stay listed in OPEN_QUESTIONS (OQ-21, OQ-22) until the owner decides.
  **B1 (Tier 3, PDF-grounded):** the signed device policy now uses format `iam-device-policy-v1`: it signs tenantId and
  deviceId (PDF 15.3 "tenant/device bound"), the heartbeat/posture intervals and failure mode (previously unsigned),
  and sorts applications as text so the signature is deterministic (the repository returned rows in no defined order).
  Timestamps are whole seconds. The agent rejects a policy that is validly signed but for another device/tenant, older
  or lower-versioned than one already accepted (replay/rollback), already expired, or seen while the clock has gone
  backwards (PDF 16 "anti-rollback"); clock-skew tolerance 120 s. Offline rules (PDF 15.2, Appendix A), implemented as a
  pure tested state machine: FAIL_CLOSED denies when the policy lapses; FAIL_OPEN allows only for the app's grace window
  (none configured = none allowed); RISK_BASED allows only if the app has offline access enabled AND is within grace;
  grace is measured from the last successful sync; an unknown mode fails closed. These govern controls enforced
  *locally by the agent*; app access is still decided server-side by the PEP.
  **B2:** produced `iam-endpoint-agent.exe` by cross-compiling on Linux (target `x86_64-pc-windows-gnu`, mingw-w64,
  static); it imports only built-in Windows DLLs. Added `--console`, `--help`, `--version`, config validation (https
  required except localhost; nil/placeholder tenant rejected; transit key must be 32 raw bytes).
  **Bugs found by running the real .exe under Wine (none were visible to the compiler or the unit tests):**
  (1) the browser was opened with `cmd /C start "" <url>`, and `cmd` treats every `&` as a command separator, so the
  sign-in URL was cut after its first parameter and the rest was executed as commands -- enrollment could never have
  worked on Windows (now `ShellExecuteW`, non-http(s) URLs refused); (2) the Windows service entry point stored the
  agent's `run` closure in a thread-local, but the service dispatcher runs `ServiceMain` on a *new thread*, so the
  service would have started and immediately stopped (now a process-wide static; Stop now actually signals shutdown);
  (3) the enrollment callback listener accepted a single connection, so a browser's speculative preconnect or any
  local process could abort sign-in (now it keeps listening and only a request carrying this attempt's secret `state`
  can complete or fail it), and it waited forever (now bounded at 5 minutes, matching the backend transaction TTL).
  **Known weak point:** hardware attributes are collected with `wmic`, which Microsoft is removing from Windows 11; it
  must move to PowerShell CIM before this is relied on.
  **Process note:** verification of an earlier step ran against stale sources because an upload failed silently; every
  verification step now first proves the VM holds the latest code (grep for a marker) and records explicit exit codes.
- **2026-11-16 -- Endpoint agent, Phase B3: device posture reporting (P1-14), Windows. Tier 3 (device-trust logic), made
  conservatively and recorded for confirmation.** The agent reports **facts only** (disk encryption, antivirus real-time
  protection, firewall, TPM, Secure Boot, OS, last update); the **server** evaluates them (`PostureEvaluator`), so a
  modified agent cannot claim to be compliant. The old API took a verdict (`postureStatus`) from the agent; that field is
  gone (a request carrying only a verdict now gets 400). Default rules: BitLocker, antivirus and firewall must all be
  enabled; any one off = NON_COMPLIANT; none off but any undeterminable = UNKNOWN (an unreadable check is never a pass,
  but is not a failure); risk 40 per failed and 10 per unknown check, capped at 100. TPM, Secure Boot and update date are
  informational only. **Enforcement is OFF by default** (`iam.device.enforce-posture=false`): the verdict is recorded and
  shown but does not change what a device may do, because turning it on suspends any approved device that fails the
  defaults (for example a laptop without BitLocker). When on, it is reversible (APPROVED <-> NON_COMPLIANT as posture
  changes) and never promotes a device that is not already approved. The non-compliant event fires when the status
  changes, not on every 15-minute report (it used to fire every time). Reported on the policy's posture interval (default
  900 s, clamped 60 s .. 24 h), after the heartbeat so a slow collection can never delay it, and still sent when the policy
  fetch fails. Collection runs fixed, input-free PowerShell scripts (`platform/scripts/*.ps1`) launched by full path under
  %SystemRoot% (never searched on PATH, since the agent runs as SYSTEM), via `-EncodedCommand`, with a 60 s timeout.
  Hardware attributes moved off `wmic` (being removed from Windows 11) onto the same mechanism. Also fixed: an invalid
  event `severity` returned 500 (now 400).
  **Verified:** Rust 91 tests; Kotlin PostureEvaluatorTest 7, DeviceTrustServiceTest 22, DevicePolicyCanonicalTest 5;
  both PowerShell scripts parse with 0 errors under the real PowerShell parser; Windows build clean; deployed, and the
  new contract and the served console bundle were checked live (404/400 behaviour as specified).
  **NOT verified:** the PowerShell probes have never run on a real Windows machine. Specifically unproven: that
  Get-BitLockerVolume succeeds under the SYSTEM account, the antivirus `productState` bit decoding (0xF000 == 0x1000 means
  on, taken from documentation, not tested), and Get-Tpm / Confirm-SecureBootUEFI on varied hardware. A probe that fails
  reports UNKNOWN, so the failure mode is "shows Unknown", not a wrong verdict.
- **2026-11-16 -- Endpoint agent, Phase B4: make the live end-to-end run possible. Tier 3 (crypto and key custody), made
  conservatively; two defects found in earlier work.**
  **Defect in the certificate code (mine, 2026-11-09):** `OpenBaoPkiClient.issueCertificate` calls PKI `issue`, which makes
  OpenBao generate a NEW key pair and return a certificate for it. The device's own enrolled key is never involved and the
  generated private key is discarded, so every certificate issued was for a key nobody holds and proved nothing about the
  device. The correct flow is PKI `sign` over a CSR created from the device's own key (so the private key never leaves the
  device, PDF section 5.3). **Decision:** certificate issuance is now opt-in and OFF by default
  (`iam.device.issue-certificates=false`). With it off, approval works with no PKI configured, the response says
  `certificateStatus: NOT_ISSUED`, and nothing is lost because nothing consumes the certificate (device calls authenticate
  by signing with the enrolled key). Building the real CSR/`sign` flow is part of the hardware-key phase (FR-5.2) and needs a
  new CSR dependency on the agent side (Tier 3), so it is not done here. An OpenBao outage now returns 503 (was 500) with no
  internal detail in the body.
  **Signed-policy key custody:** policies are signed by an Ed25519 key `device-policy` in OpenBao's transit engine; the
  private key never leaves OpenBao. `infra/openbao/device-trust-setup.py` creates it (idempotent) and adds ONE permission,
  `transit/sign/device-policy` (capability `update`), to the shared `cert-issuer` policy by reading and appending, never
  replacing (replacing would cut every service off from its secrets). Limitation inherited from the existing design: all
  services share one AppRole, so every service can sign device policies, not only iam-tenant-svc; a dedicated AppRole would
  be the least-privilege fix.
  **Verified against a REAL OpenBao** (same `openbao/openbao:latest` image the platform runs, throwaway dev instance): the
  script succeeds on run 1 and changes nothing on run 2; existing policy paths are preserved; a token holding the policy can
  sign with `device-policy` (200) but cannot read the key, use another key, or create keys (403); and a signature produced by
  the real transit API over the golden canonical string verifies in the Rust agent, while a tampered policy is rejected. The
  live OpenBao has NOT been changed: running the script needs the root token, which only the operator should use.
  **Process failures this phase (recorded so they are not repeated):** (1) two verification harnesses silently did nothing
  because inline Python was run with `docker run` without `-i`; one was caught only because the next step failed loudly, so
  harness steps now assert their expected output; (2) a deploy bundle of a whole directory copied OpenBao's `init.json` and
  test client key into world-readable `/tmp` files on the VM for ~4 minutes (see OQ-27); archives for the VM now list files
  explicitly.

- **2026-11-16 -- Endpoint agent: browser sign-in restriction for Chrome and Edge (spec P1-19, P1-20, P1-23, partial). Tier 2.**
  Uses the browsers' own enterprise policy (AP-7, no TLS inspection): HKLM `RestrictSigninToPattern` for Chrome and Edge and
  Chrome `AllowedDomainsForApps`, written by the SYSTEM service at every start so a changed value is restored. The domain
  list comes from the local `allowed_identity_domains` in `config.json` (empty = feature off, nothing touched); domains are
  strictly validated because they end up in a regex. Unit-tested (5 tests, 96 total) and cross-compiled for Windows; the
  registry write has NOT been run on a real machine and Chrome's behaviour (`chrome://policy`) has not been checked.
  Not done: Firefox, Safari, other providers, removing the values on uninstall, and delivering the list through the signed
  device policy instead of local config (needs a change to the signed canonical format on both sides: Tier 3, see OQ-28).
- **2026-11-16 -- Endpoint agent: tamper detection (spec P1-16, partial). Tier 2.** The agent hashes its own program and
  `config.json` at start and re-checks every sync tick. A change or deletion raises one CRITICAL `agent.tamper_detected`
  event per distinct state and turns the heartbeat health to DEGRADED until the file matches again (`agent.tamper_cleared`).
  A legitimate edit or update is followed by a restart, which takes a new baseline. 5 new tests (101 total); verified on real
  Windows by editing the config while the agent ran (HEALTHY -> DEGRADED on the demo platform). NOT covered: stopping or
  killing the service, SYSTEM-level replacement of files plus restart, signed-binary checks, a watchdog, and the spec's
  "configurable response" (only report + degrade is built).
- **2026-11-16 -- Endpoint agent: `--status` command (surfaces the offline/failure-mode logic, spec P1-17/P1-18). Tier 2.**
  Read-only summary from local files only: enrollment, key type, signed policy version and freshness, intervals, the offline
  behaviour (fail-closed / fail-open / risk-based, per-app grace) and the local decision right now. Never prints key material
  (tested). 6 new tests (107 total); run on real Windows against the demo state. The decision logic itself (`PolicyCache::decide`)
  already existed and is unit-tested; nothing on the device ENFORCES it yet, because enforcement belongs to the browser/network
  controls (P1-19..25) that are mostly unbuilt. When installed the data folder is administrators-only, so `--status` needs an
  administrator shell.
- **2026-11-16 -- Endpoint agent: heartbeat cadence fix and browser-policy cleanup on uninstall. Tier 2.** The sync loop now
  measures its interval from the START of a pass, so slow posture collection (~12 s of PowerShell) no longer stretches the
  heartbeat (was ~42 s against a 30 s policy; measured on real Windows after the fix: 30 s gaps, 4 of 4). `install.ps1 -Uninstall`
  removes the three browser policy values when the config had allowed_identity_domains (it removes by name, so a value an
  administrator set independently under the same name would also go; documented, not yet verified on a real machine).
- **2026-11-17 -- Endpoint agent: Windows Event Log integration (spec Section 14.1). Tier 2.** Every event the agent raises
  (tamper detected/cleared, policy rejected, clock moved backwards, posture collection failure) plus agent started/stopped and
  the browser-policy result is mirrored to the Windows Application log under source `IamEndpointAgent`, with stable ids
  (1000 started, 1001 tamper detected, 1002 tamper cleared, 1003 policy rejected, 1004 clock moved backwards, 1005 posture
  failure, 1006 stopped, 1010/1011 browser policy applied/failed, 1999 other). 111 tests (4 new + one extended). Verified on
  real Windows: events 1000 and 1001 appeared in Event Viewer with the right level and text. The source has no message file,
  so Event Viewer prints its "description cannot be found" preamble before the agent's text; registering a message file is a
  later polish item. `agent.stopped` is not written when the process is killed (only on a graceful stop).
- **2026-11-17 -- Device activity timeline (Admin Console + iam-tenant-svc). Tier 2.** New admin-only endpoint
  `GET /api/v1/endpoint/devices/{id}/events?tenantId=` (the device's 50 most recent events, newest first; another tenant's
  device looks like "not found") and an "Activity" list under each device's details. Admin actions (approve, reject, suspend,
  revoke) were audit-log-only; they are now ALSO written to the device's own event table (with the actor and reason), so the
  timeline shows who did what. 3 new tests; the full tenant test suite passes on the VM. Deployed to the live VM (tenant-svc,
  then admin-console). Verified: both healthy and the new route exists and rejects a caller with no session (HTTP 400).
  Not yet seen in the browser by me. Events written before this change for admin actions do not exist (they were never stored
  there), so older devices show enrollment/agent events only.
- **2026-11-17 -- Endpoint agent: unsigned MSI installer (spec P1-02, partial). Tier 2.** Built with the portable WiX 3.14 toolset
  (downloaded into %LOCALAPPDATA%\iam-build-tools, nothing installed system-wide; the zip's SHA-256 was recorded at download,
  trust-on-first-use, no published checksum was checked). `install/build_msi.ps1` produces `dist/IamEndpointAgent-<version>.msi`
  with tenant id, policy key, allowed domains and URLs as DEFAULT properties that a silent install can override
  (`msiexec /i ... /qn TENANT_ID=... POLICY_KEY=... ALLOWED_DOMAINS=...`). It installs to Program Files, registers the
  auto-start LocalSystem service with restart-on-failure, writes the locked-down config through `configure.ps1` (strict input
  validation, tested with bad tenant/key/URL/domain), keeps an existing config on upgrade, adds a Start Menu "Enroll this
  device" shortcut, upgrades in place (MajorUpgrade) and on uninstall removes the service, files and browser restriction.
  The MSI deliberately does NOT start the service: enrolment needs the user's browser sign-in, which an installer running as
  SYSTEM cannot do, so `Enroll-Device.cmd` enrols (default BYOD = manual approval; CORPORATE auto-approves) and then starts it.
  NOT signed (no certificate): Windows shows "Unknown publisher"; signing later is one command, no rebuild. NOT yet installed
  or run on a real machine: the build shell was not elevated, so only the build, the MSI contents (decompiled with WiX dark)
  and the script validation were verified. An MSI cannot be installed over an agent installed by install.ps1 (the service
  already exists); uninstall that first.
- **2026-11-17 -- Admin Console, Endpoint Security: fleet summary, Offline flag, search, auto-refresh. Tier 2.** Console-only
  change (no backend change). Summary cards (Devices, Approved, Awaiting approval, Non-compliant, Offline) that double as
  filters, a search box (device name or user), and an "Offline" badge on any device not seen for 15 minutes (the default
  heartbeat is 5 minutes), which makes a stopped or killed agent visible -- until now the platform only showed a stale "Last
  seen". The page also refreshes itself every 30 seconds. The 15-minute threshold is a display rule only; no enforcement uses
  it. Type-checks (tsc) and is deployed; the console's own test suite has one failure that predates this change
  (tenant.test.ts: the dev `?tenant=` override wins over a real subdomain, which contradicts that test; see the sslip.io
  demo-domain entry above) and was left alone.
- **2026-11-17 -- Endpoint agent polish round (usability, PDF 6.3). Tier 2.**
  (1) Re-enrolment: `--enroll` on an already-registered machine now says so before opening anything and exits 3, which
  `install.ps1` and `Enroll-Device.cmd` treat as success (so reinstalling on a registered machine just starts the service);
  `--reset-enrollment --confirm` deletes `state.json` and `policy-cache.json` (keeps config) so the machine can enroll as a
  NEW device, and refuses while the service is running; the old platform record is left for an administrator to revoke.
  (2) Security fix: `--ownership` used to treat ANY value other than the exact text `BYOD` as CORPORATE, which the platform
  approves automatically (a typo meant auto-approval); unknown values are now refused (exit 2).
  (3) Bug fix in `Enroll-Device.cmd` (never run yet): its self-elevation passed an empty `-ArgumentList`, which PowerShell
  rejects, so the Start Menu shortcut would have done nothing on a non-elevated click.
  (4) README rewritten to describe the real install/use/remove flow.
  Considered and NOT changed: the BitLocker probe takes ~5.5 s (module load); a faster CIM query exists but can only be
  verified as administrator, and the current probe reads correctly on the test laptop, so it stays.
  113 tests pass; checked on Windows: already-enrolled exit 3, bad ownership exit 2, reset without --confirm exit 2, and the
  reset refusing while the real service runs. The reset deletion itself is covered by unit tests only.
- **2026-11-17 -- Device-bound sign-in and TPM keys: design agreed, slice S1 built. Tier 3 decisions made by the owner.**
  Owner decisions: (D1) proof of the laptop = the agent signs a one-time platform challenge over a 127.0.0.1 endpoint (PDF 4.2 "nonce-based signed challenge"); (D2) device state blocks only apps an admin flags "trusted device required"; (D3) TPM-backed ECDSA P-256 keys with a software fallback and the assurance level reported; (D4) a non-compliant laptop is blocked only from flagged apps, no automatic suspension. Full design, API, audit events and success criteria in `docs/specs/device-bound-signin-SPEC.md`.
  Built and tested (S1, tenant-svc only, 16 new tests, whole suite passes on the VM, NOT deployed): migration V11 (per-app flag on oidc_clients and saml_sps; one-time challenge table); `DeviceLoginProofService` (issue; verify with atomic single use that burns the challenge even on failure, same-tenant AND same-user device, dead states refused, domain-separated payload bound to tenant, user, device, challenge, nonce and origin, generic 401 outward with the real reason audited); `TrustedDeviceGate` (applies to administrators too; denies no-device, unknown, not-approved, non-compliant, someone else's device; audited); `PUT /{id}/trusted-device` on OIDC clients and SAML apps; the session's deviceId now reaches the access check. The gate sits in `AppAccessController`, not `AppAccessService`, so the existing access tests and rules are untouched.
  Not built yet: auth-svc accepting the proof (S2), console switch (S3), the agent's loopback endpoint (S4), the login-portal flow (S5), TPM keys (S6; note CNG signs ECDSA as raw r||s while the backend's `SHA256withECDSA` expects DER, so the verifier needs `SHA256withECDSAinP1363Format` for this path), end-to-end run (S7). Until S2-S5 exist nothing sets a deviceId on a session, so flagging an app today would lock everyone out of it: do not switch the flag on before S5 is deployed.
- **2026-11-17 -- Device-bound sign-in: S1 corrected and deployed, S2 built and deployed. Tier 2.**
  (1) Design flaw fixed before it shipped: the challenge was bound to a user, but the login page asks for it BEFORE the
  password is checked, so the user is unknown. Now the challenge belongs to the tenant only; auth-svc, which has authenticated
  the user, tells tenant-svc which user the laptop must belong to (the device's owner must equal that user); the signed payload
  no longer contains a user id.
  (2) A real exposure found by checking the live system and closed the same day: the spec said the new `/internal/device-challenges`
  routes were not publicly routed, but the public proxy forwards every request for the tenant address, so they answered the
  internet (HTTP 200). A proof still cannot be forged (a valid device signature is required) but anyone could create challenge
  rows. `InternalOnlyFilter` now answers 404 to any request carrying a proxy header (`X-Forwarded-*`, `Forwarded`, `X-Real-IP`);
  verified live: 404 from the internet, 200 from inside the platform network. Limited to the new routes on purpose; the older
  `/internal/devices/...` route (OQ-24) is unchanged and still publicly reachable.
  (3) S2: `iam-auth-svc` accepts an optional `deviceProof` on login. It is checked only after the password and second factor have
  succeeded; success stores the device on the session; a missing, wrong, malformed-but-parsed or unverifiable proof (or an
  unreachable tenant-svc) NEVER changes the outcome of the sign-in: the person signs in without a device and a
  `auth.device_proof_not_accepted` audit event is written. The existing `issue` path is untouched; a separate `issueForDevice`
  is used only when a proof verified. tenant-svc has its own breaker and `max-attempts: 1` (a challenge is single use, and a slow
  tenant-svc must not slow sign-ins). 6 new auth tests; both suites pass on the VM.
  Verified live after each deploy: tenant, admin console and login portal respond; a login for a made-up user returns the same 401
  with and without a bogus proof; a malformed proof returns 400. A real person's sign-in was not exercised by me.
  Nothing sets a deviceId on a real session yet (the login page and agent are S4/S5), and no app is flagged, so user-visible
  behaviour is unchanged.
- **2026-11-17 -- Device-bound sign-in S4: the agent's loopback endpoint. Tier 2/3 (a new local network surface), built conservatively.**
  `crates/agent-core/src/local_api.rs`: a minimal hand-written HTTP/1.1 listener on 127.0.0.1 (ports 47631-47635, first free; no
  new dependency). Routes: `GET /v1/identity`, `POST /v1/sign-login`, CORS preflight. Restrictions: Host must be exactly the
  loopback address and port (DNS rebinding), Origin must equal the origin of `enrollment_login_url` (else 403 with no CORS headers),
  JSON content type required, strict body validation (`deny_unknown_fields`, UUID challenge id, 16-128 char base64url nonce, body
  origin must equal the allowed origin), 4 KiB body / 8 KiB head caps, 3 s read timeout, 8 concurrent connections, peer must be
  loopback. It signs ONE fixed structure (`iam-device-login-v1` + tenant, device, challenge, nonce, origin) and nothing else; the
  platform accepts only challenges it issued. It can be switched off per machine with `local_api_enabled: false`. A failure to bind
  never affects the agent's normal reporting.
  Stated limit: software running on the laptop can send any Origin header; it would still need a live platform challenge and the
  user's password, so it gains nothing it did not already have, but this is not protection against local malware.
  Verified: 14 unit tests plus 4 real-socket tests (129 agent tests total). On real Windows, against the demo platform: right
  origin 200 and a signature that an independent Python implementation verified over the exact payload (and that does NOT verify
  for a different origin); evil origin, missing origin 403; bad nonce 400; wrong body origin 400; bound to 127.0.0.1 only.
  Your installed agent does not have this yet: it needs a new version (bump from 0.1.0) installed over it. Not done on purpose
  before the login-page side (S5) exists.
- **2026-11-17 -- Device-bound sign-in S3: Admin Console switch. Tier 2.** On each connected app's details row (Clients page) a
  "Trusted device" checkbox: "Only allow sign-in from an approved, compliant laptop". Turning it ON asks for confirmation and warns
  that administrators are included and that the team must have the agent; turning it off needs none. Off by default for every app.
  Calls `PUT /api/v1/{oidc-clients|saml-sps}/{id}/trusted-device`. Type-checks and deployed (the console's one failing test,
  tenant.test.ts, predates this). DO NOT turn it on for any app until S5 (login page asks the agent for proof) is deployed and the
  new agent is installed: until then no session carries a device and the app would refuse everyone.
- **2026-11-17 -- Device-bound sign-in S5: the login page asks the agent for proof. Tier 2, built so that nothing changes until it is used.**
  Rules the owner set: do not disturb the existing sign-in, laptop apps or the admin console. How that is guaranteed:
  (1) the portal talks to the agent only when the tenant has at least one app flagged "trusted device required" (new internal
  `GET /internal/device-challenges/required`); the check fails to false, so any fault means "behave as before"; no app is flagged
  today, so no page makes a local call or shows anything new. (2) A proof can only ADD a device: the browser code never throws, has
  a 4 s overall limit and 0.8 s probe limit, and always submits the form afterwards, with the same button, even on failure; the
  server drops any proof that is not exactly well-formed (iam-auth-svc would answer a malformed proof with 400, which would block
  the sign-in). (3) The admin console signs in by calling iam-auth-svc directly and never sends a proof, so it cannot be affected.
  The challenge is fetched at submit time (not page load) because it may be a minute between password and code; lifetime raised
  from 60 to 120 s for the push path (which can wait 60 s on the phone before verification), and old challenges are deleted on issue.
  Verified: 62 portal tests (9 new), tenant suite on the VM (3 new); deployed in order tenant-svc then portal; live sign-in pages
  are byte-identical to before apart from one new empty hidden field and Next's per-build action id; the new internal routes answer
  false/200 inside the network and 404 from the internet; wrong-password login still 401; admin console, device list and the laptop's
  agent unaffected. NOT yet exercised end to end: needs the new agent installed and an app flagged (see OQ-31 for the browser's
  possible local-network prompt, which would then appear for the tenant's sign-in page).
- **2026-11-17 -- TPM-backed device keys (spec P1-06, section 5.3), agent 0.2.0. Tier 3 (key custody), per owner decision D3.**
  New enrollments use a TPM key when the machine has one, otherwise the software key, with the assurance level reported
  (`HARDWARE_TPM` / `SOFTWARE`) and shown in the console. Windows CNG, "Microsoft Platform Crypto Provider", ECDSA P-256, created as a
  MACHINE key (so the LocalSystem service can use a key an elevated administrator created), never exportable. State: `state.json` gains
  an optional `hardware_key_name` next to the existing optional `key_material` (both `serde(default)`; an old file loads unchanged, tested);
  a TPM identity stores no private key bytes at all (tested). Rules: only NEW enrollments change; an existing software identity keeps
  its key even where a TPM exists; a TPM key that cannot be opened is an error and is never silently replaced by another key (that
  would be a different identity the platform never registered); if enrollment fails after the key was created the key is deleted;
  `--reset-enrollment` deletes the identity's TPM key; `prefer_hardware_key: false` in config forces software keys.
  Signature format: CNG signs ECDSA as raw 64-byte r||s; the backend verifier now picks `SHA256withECDSAinP1363Format` for a 64-byte
  signature and DER otherwise (tested both, plus tampered, wrong key, garbage); Ed25519 is unchanged. New dependency: none (windows-sys
  gains the `Win32_Security_Cryptography` feature; the binary crate gains the already-used `sha2`).
  New command `--tpm-selftest [--user]` creates a throwaway key, signs, reopens, deletes, and prints the public key and signature as JSON.
  Proven on the dev laptop (user-scope key, real TPM): created, signed, reopened, deleted; the SPKI and signature were verified
  independently by Python's `cryptography` AND by Java's own KeyFactory/Signature exactly as the backend reads them; tampered data fails.
  NOT yet proven: a machine-scope key (needs an elevated shell: run `--tpm-selftest` as administrator), the SYSTEM service using it,
  and a whole TPM enrollment against the real platform; the 140 agent tests use a fake TPM store for the logic. A laptop with no TPM, or a
  VM, falls back to a software key (the fallback path is unit-tested, not run on such a machine).
  Also this round: version 0.2.0 (so the MSI upgrades 0.1.0 in place); the MSI now starts the service after an upgrade, but only if the
  machine is already enrolled (a fresh install must not start it before enrolment). Fixed my own mistake in that edit: a Python string
  turned `\v1.0` into a control character in the PowerShell path; found because the build failed.
- **2026-11-17 -- BUG FOUND AND FIXED (mine): device policy signing was lost at every VM reboot. Tier 2.** Symptom: after the VM restarted
  (scheduled stop/start), iam-tenant-svc logged `OpenBao ... Signing via transit failed: 403 permission denied` and the laptop agent could
  no longer obtain a signed policy (it retried with backoff, about every 10 minutes). Cause: `infra/openbao/unseal-on-boot.sh` runs
  `bootstrap.py` on EVERY boot and `ensure_approle` REPLACES the whole `cert-issuer` policy from the constant `CERT_ISSUER_POLICY`;
  my `device-trust-setup.py` only appended `transit/sign/device-policy` to the LIVE policy, so the next boot silently removed it.
  I recorded in OQ-25 that the setup script should be re-run after a rebuild, but did not check the boot path. Fix: the permission is
  now part of `CERT_ISSUER_POLICY` in `bootstrap.py` (repo and the VM's copy; the VM file differed from the repo only by these 7 lines;
  backup at /tmp/bootstrap.bak.* on the VM, which does not survive a reboot). `device-trust-setup.py` stays idempotent (it detects the
  permission and changes nothing). What stays unaffected by this fault: sign-in, the admin console, device registration, heartbeats and
  posture (device-signed, not OpenBao-signed). What it broke: only the signed policy the agent verifies, so the agent showed degraded.
  The live policy still lacks the permission until the setup script is run once with the root token (operator step); after that a
  reboot keeps it. Lesson: any change to a resource that a boot script re-asserts must be made in that script's source, and a verified
  claim about "survives restart" needs an actual restart test (tonight's unplanned restart was the test).
- **2026-11-17 -- Fixed an OLD bug found during the E2E test: saving an app's group access failed whenever the selection kept an
  already-assigned group. Tier 2 (bug fix, not part of device-bound sign-in).** `OidcClientService.setGroups` and `SamlSpService.setGroups`
  deleted the app's group rows and inserted the new set in one transaction; Hibernate executes INSERTs before DELETEs at flush, so any
  selection overlapping the existing one violated the unique index (`idx_oidc_client_groups_unique`), HTTP 500, which the console shows as
  "This is temporarily unavailable". Present in the last commit (not introduced by this work); it only ever worked when the new selection
  shared nothing with the old. Found because the log showed three such errors while the owner saved OU access for the test app. Fix: flush
  the delete before saving (one line in each service) plus two ordering regression tests; whole tenant suite passes; deployed.
  NOT investigated: whether the OUs page uses a different endpoint with the same shape (the "APPS THIS OU CAN OPEN" checkboxes call
  per-app group updates, so it is likely fixed by the same change, but not verified).
  Also seen live: Chrome shows a "wants to access other apps and services on this device" (local network) permission prompt the first
  time the sign-in page contacts the agent (OQ-31 confirmed). If it is not answered within the 4 s overall limit the proof is skipped and
  the sign-in carries on without a device, so a flagged app then shows the generic access-denied page (OQ-34).
- **2026-11-17 -- Device-bound sign-in: first live attempt failed; design flaw in S5 found from the platform's audit stream and fixed. Tier 2.**
  Evidence (audit events read from the `audit-events` Kafka topic): the owner's sign-ins succeeded and the group check passed, but
  `app.access.denied_untrusted_device` fired with no device on the session, and there was NO `auth.device_proof_not_accepted` event, so
  the portal never sent a proof at all. Cause: Chrome asks the person to allow a site to reach "other apps and services on this device"
  the first time it does so, and S5 made that first call at the moment of Sign in with a 0.8 s probe limit, so nobody could answer in time
  (and each new InPrivate window starts again). The refusal page is the generic "no access" one, which looked like a group problem (OQ-34).
  Fix: the sign-in page now touches the agent once when it loads (only for tenants that use device sign-in), so the prompt appears while
  the person types; at sign-in a still-unanswered prompt gets up to 15 s (22 s overall) and otherwise the usual 4 s. Still never blocks a
  sign-in. 5 more portal tests (67). Lesson: the unit tests proved the logic but not the browser's permission timing; only a real browser
  run showed it, which is why S7 exists. Possible follow-up for managed laptops: pre-approve the login origin through browser policy so
  there is no prompt at all (the agent already writes Chrome/Edge policy); not done, the exact policy name/version needs checking first.
- **2026-11-18 -- Login portal: the refusal page now says WHY (closes OQ-34's wording half). Tier 2.** An app refusal used to show
  "add you to a group" whatever the cause, which made the device test look like a group problem. iam-oidcprovider-svc already passed the
  gate's reason as the error message; the portal now maps it to one of a FIXED set of codes (`device_required`, `device_unregistered`,
  `device_not_approved`, `device_noncompliant`, else `app_access_denied`) with fixed wording. Backend text is never shown and never put in a
  URL (the error page is reached by URL, so it must not echo anything a link could carry). Same mapping on the SSO path, the OIDC form path
  and the SAML form path. Also fixed an existing bug: `/login/error?reason=toString` rendered an empty message (object prototype lookup);
  the page now accepts only its own keys. 4 new tests (71); deployed; every code checked on the live page. The coupling (portal matches
  the gate's phrases) is commented at both ends; a wording change can only make the page fall back to the generic text.
- **2026-11-18 -- P1-13 application-specific pending-device access (spec 6.4). Tier 2.** Spec 6.4: "Application-level policy determines
  what a pending device can access (e.g. HR and IT support allowed; CRM, Finance and source code blocked). All final decisions must be
  enforced by the backend PEP." Built as a per-app `allow_pending_device` (migration V12, OIDC and SAML, default FALSE) that only matters
  together with `require_trusted_device`. The gate accepts APPROVED, plus PENDING_APPROVAL only where the app allows it; suspended,
  revoked, rejected or decommissioned laptops stay refused whatever it says, and a pending laptop that fails posture is still refused.
  Admin endpoint `PUT /{id}/pending-device` (admin only); console checkbox "Also allow laptops that are still awaiting approval" under
  Trusted device, disabled while Trusted device is off. 5 new gate tests; tenant suite passes; deployed (tenant-svc, then console); the
  test app shows `allowPendingDevice: false` (safe default) from the live API. Not run end to end with a real pending laptop (the only
  enrolled laptop is approved). The signed device policy's per-app `pending_access` field (agent side) is unchanged: the decision is the
  backend's, as 6.4 requires.
- **2026-11-18 -- P1-16 "configurable response" to tampering. Tier 2.** iam-tenant-svc setting `iam.device.tamper-response`
  (env `IAM_DEVICE_TAMPER_RESPONSE`): `report` (default; record and show, as before) or `suspend` (also suspend an APPROVED device,
  recorded as an AUTOMATIC suspension by `system:tamper-response` with the reason, audited as `device.suspended`). Never undone
  automatically by `agent.tamper_cleared`: an administrator reviews and reactivates. Only approved devices are touched; any value other
  than `suspend` (including typos) means report, so a misconfiguration cannot lock devices out. Same shape as the existing
  `enforce-posture` switch. 4 new tests; suite passes; deployed with the default (no behaviour change). Not set per tenant: one setting
  for the whole deployment until tenant-level device settings exist. Still not covered: stopping or killing the agent service, and file
  replacement by someone with SYSTEM rights followed by a restart (the agent re-baselines at start).
- **2026-11-18 -- Owner decisions (Tier 3), recorded before building:** (1) P1-26 agent auto-update: releases are signed by a NEW,
  separate OpenBao transit key `agent-release` (not the policy key). (2) P1-17/P1-18 offline/failure modes stay REPORT-ONLY on the laptop
  (the decision is computed and shown; nothing on the device is blocked; the platform-side checks protect "trusted device" apps). This is
  the chosen behaviour, not a gap. (3) P1-16 tamper response stays `report` (auto-suspend is built but off). (4) P1-21 Firefox and P1-24
  Microsoft tenant restrictions are deferred: Firefox needs Mozilla-signed extensions and Tenant Restrictions needs Entra admin setup.
- **2026-11-18 -- P1-26 signed agent updates built (0.3.0), per owner decision: a NEW OpenBao key `agent-release`. Tier 3 (it installs
  code as SYSTEM), designed conservatively; spec in `docs/specs/agent-update-SPEC.md`.**
  Trust model: the OPERATOR signs, with their own token at publish time; no service has permission on that key (the setup script
  refuses to finish if the shared `cert-issuer` policy could ever sign with it, and a service-level token was shown to get 403), so a
  compromised iam-tenant-svc can serve a file but cannot make an agent accept one. The AGENT decides: signature over
  `iam-agent-release-v1 / platform / arch / version / sha256` against the key in its administrators-only config, hash of the bytes (checked
  again from disk, to catch a swap), and a strictly newer version (no downgrade or replay of an old signed release). Signature and
  version are checked BEFORE downloading. No key configured = updates off, and nothing the platform sends can turn them on.
  Backend (deployed): migration V13 (signature column, package table), `AgentReleases.kt`: operator publish route
  `/internal/agent-releases` (answers 404 through the public proxy; recomputes the SHA-256 and refuses a mismatch or a duplicate version)
  and two device-signed agent routes (offer, download). Agent: `update.rs` (20 unit tests, a fake source/installer for every refusal,
  a paused-clock test of the 5 minute / 6 hour schedule), windows `msiexec /i /qn` launched detached by full System32 path for a verified
  `.msi` only. Operator tools: `infra/openbao/agent-release-setup.py`, `infra/agent-release/publish.py` (7 tests).
  Verified against a REAL OpenBao (throwaway, same image as production): setup is idempotent; the guard refuses a dangerous policy; a
  service token is refused (403); publish.py signs a real installer through transit; the agent's verifier accepts that signature and
  rejects a tampered file, a changed version and a same-version replay. Installer: an upgrade now KEEPS the existing config.json (before,
  a reinstall rewrote it from build defaults, which would have wiped local settings on every automatic update) and only adds a missing
  release key; `FORCE_CONFIG=1` rewrites on purpose; 13 behaviour tests of the script. Version 0.3.0. See OQ-35 to OQ-38 for limits.
- **2026-11-18 -- Pre-publish rehearsal on the dev laptop FOUND AND FIXED TWO SERIOUS INSTALLER BUGS (mine). Tier 2, but one of them could have
  left laptops with no agent.** Rehearsing the MSI upgrade 0.2.0 -> 0.3.0 on the real laptop:
  (1) **Bug in my config step.** The installer passed `-ReleaseKey "-"` (a lone dash as the "no key" placeholder) to PowerShell, which parses
  it as a broken parameter name; `configure.ps1` crashed and failed the whole install (error 1603). My earlier script tests called the script
  with splatted parameters, never through `powershell -File` as Windows Installer does, so they could not see it. Fix: placeholder `NONE`;
  and the config step now NEVER fails an install on a machine that already has a config (every problem there is reported and ignored; only a
  fresh install may fail loudly). 7 new tests run the script exactly as the installer does.
  (2) **A failed upgrade removed the working agent.** With the default MajorUpgrade order (remove old, then install new), the failure made
  Windows roll back and the rollback did NOT restore the old version ("Error in rollback skipped"): the laptop ended with no exe, no service and
  no Apps entry (only the identity files in ProgramData survived, which is why reinstalling worked). For a product with AUTOMATIC updates this
  would have silently unprotected laptops on any failed update. Fix: `MajorUpgrade Schedule="afterInstallExecute"` (install the new version
  first, remove the old one only afterwards), proved with a deliberately failing test installer (`build_msi.ps1 -FailInjection`, never in a
  release): the failing 0.3.9 returns 1603 and 0.3.0 stays installed and running with the same identity; a good 0.3.1 upgrade then succeeds with
  one Apps entry. (3) The installed file name now follows the build's source file name; pinned to `iam-endpoint-agent.exe` in the installer
  (the service, shortcut and later upgrades rely on it). The MSI version is also now passed to build_msi as `-ExePath` for rehearsal builds.
  Also proven live on the laptop: MSI uninstall removes the service, folder, Start Menu entry and the Chrome/Edge policies and KEEPS the config
  and identity; a clean reinstall on an enrolled machine starts the service by itself.
  **TPM enrollment proven on the real TPM** (P1-06): a machine-scope ECDSA P-256 key, assurance HARDWARE_TPM, no private key bytes in the
  identity file, every signed request (heartbeat, policy, posture, enrollment proof) accepted by an independent verifier (Python `cryptography`)
  with 0 rejections; the test key was deleted afterwards. Limits: `--reset-enrollment` refuses while the real service runs, so its TPM-key
  deletion is unit-tested only; the cleanup used `certutil -delkey`.
  Process lesson, for the log: test an installer the way the OS runs it (an actual upgrade, an actual failed upgrade), not only its parts.
- **2026-11-18 -- Agent-driven update rehearsed on the real laptop (P1-26).** A separate rehearsal agent (0.3.0, throwaway folder, throwaway
  release key, demo platform) found a signed REAL 0.3.2 installer, verified it, launched `msiexec` silently and the installed agent was upgraded
  0.3.1 -> 0.3.2: service restarted by itself (agent events 1020 installing, 1006 stopped, 1000 started 0.3.2, 1010 browser policy), one Apps
  entry, correct exe name, the real device identity and config fingerprints unchanged, `--status` shows the same device
  (`ef9a4d16…`), APPROVED, policy valid, local decision ALLOW. The rehearsal never put its test key into the real install. NOT yet proven: the
  installed SERVICE replacing ITSELF from the real platform with the real OpenBao-signed release (the rehearsal agent was a different process
  from the service being replaced); that is the first real publish. Also noted while checking: my rehearsal script briefly pointed
  `--status` of the real exe at the rehearsal's data folder and printed the rehearsal's device; a harness artefact, not a product fault.
  State after the rehearsal: real agent 0.3.2 (software key, auto-update OFF until the real release key exists), 0 leftover TPM keys.
- **2026-11-18 -- P1-26 PROVEN LIVE: the installed SERVICE replaced itself from the real platform with a release signed by the real OpenBao key.**
  Operator side: `infra/openbao/agent-release-setup.py` created the `agent-release` key (it confirmed no service policy can sign with it);
  a `--dry-run` signature over the 0.3.3 installer was verified independently (Python `cryptography`, and the agent's own Rust verifier on the
  real file) BEFORE anything was installed or published; the key's public half was typed from a screenshot, which is why it was proven
  cryptographically instead of trusted. `publish.py` then uploaded release 0.3.3. Laptop side: the key-bearing 0.3.2 baseline was installed
  (identity untouched, only the key added to the config), the service's first update check ran 5 minutes after it started, and the laptop went
  0.3.2 -> 0.3.3 by itself: agent events 1020 `update_installing`, 1006 stopped, 1000 started 0.3.3, 1010 browser policy; one Apps entry; the
  downloaded installer hashes to the signed checksum (`fba1d909…ff4362`); the MSI log says "Installation completed successfully"; the device is
  still `ef9a4d16…`, APPROVED, policy valid, local decision ALLOW; identity fingerprint unchanged.
  Two operator-tool faults found on the way, both mine and both fixed: (1) `publish.py` used `docker` without `sudo` (the operator account is not in
  the docker group) and printed an empty "HTTP ?" error, so it now uses `sudo` and prints the real error text; (2) a release key typed from a
  screenshot cannot be trusted by eye, and a key starting with `/` is rewritten by Git Bash's path conversion when passed as an argument; the MSI
  build now validates `-ReleaseKey` (base64, exactly 32 bytes) and refuses a bad one at build time.
  Still open (OQ-35 to OQ-38): no automatic return to an older version if an update installs and then misbehaves (a failed INSTALL is safe, proven);
  the installer is not Authenticode-signed; releases are served from the database; one release stream for all tenants.

- **2026-11-18 -- Admin console: "Remove device" (decommission) and the device identity panel (spec 6.2, 13.2, 5.1). Tier 2.**
  The demo needs a laptop to be re-registered from scratch. First version was a "Delete" button that hard-deleted the device and all of its
  rows (approvals, keys, hardware, posture, events). That was wrong against the spec: 6.2 says DECOMMISSIONED must "retain audit record", and
  AP-8 wants admin actions immutably audited. It was also deployed without being logged here. Replaced by `POST /devices/{id}/decommission`
  (`DeviceTrustService.decommission`): the device becomes DECOMMISSIONED, its certificate is revoked, nothing is deleted, the audit event
  `device.decommissioned` is published, and the call is idempotent. A decommissioned device never satisfies the trusted-device gate and is
  excluded from the per-user device cap (it was already in TERMINAL_STATUSES). The Endpoint Security page hides decommissioned devices
  by default and shows them under "Show removed devices". To register the same laptop again: `--reset-enrollment --confirm` on it (new agent
  installation ID, so a new device record; enrolling with the same installation ID would hit the unique (tenant, installation id) constraint),
  then enrol and approve. The agent on a decommissioned device can still heartbeat (its key stays active, as for REVOKED); it cannot change the
  status back, because posture enforcement only moves APPROVED <-> NON_COMPLIANT.
  The same change adds the layered identity of spec 5.1 to the Details panel (platform device_id, agent installation UUID, key algorithm and
  assurance level, versioned SHA-256 fingerprint, manufacturer/model; hashes only). Also removed a "download the installer" link from the
  Install guide popup that pointed at a route that does not exist.
  Tests: three new `DeviceTrustServiceTest` cases (retires + revokes certificate + never deletes; idempotent; wrong tenant refused); run on the
  VM with the other device suites: 50 tests, 0 failures. Not yet done from spec 13.2: a reason prompt on privileged actions, "force policy sync",
  "request re-enrolment", the platform/enforcement-capability inventory fields.

- **2026-11-19 -- Admin console: time-limited compliance exception for one device (spec 6.2, 6.4, 13.2). Tier 3, scope chosen by the user.**
  Request: let an admin allow a laptop that fails the required security checks (BitLocker / firewall / antivirus) to keep using apps that
  require a trusted device. This deliberately loosens a device-trust rule, so the three open choices were put to the user and answered:
  scope = ONE DEVICE (not an app, not a user); duration = admin picks 1, 7 or 30 days (hard maximum 30, ends by itself); reason = REQUIRED.
  Behaviour: `POST /devices/{id}/compliance-exception {days, reason}` and `.../compliance-exception/remove` (tenant admin only), stored on
  `iam_devices` (V14: `compliance_exception_until/_reason/_by`). `TrustedDeviceGate` treats an unexpired exception as waiving ONLY the compliance
  check (the NON_COMPLIANT posture, and the NON_COMPLIANT lifecycle state that posture enforcement sets). It never helps a pending, suspended,
  revoked, rejected or decommissioned device, another user's laptop, or a sign-in with no verified device proof, and it does not stop the device
  being flagged non-compliant in the console. Granting is allowed only for APPROVED / NON_COMPLIANT devices; granting again replaces the end date;
  an expired exception reads as none everywhere (gate, console). Audit: `device.compliance_exception.granted` (actor, days, end date, reason),
  `device.compliance_exception.removed`, and `app.access.allowed_compliance_exception` each time the exception is what let a sign-in through, so every
  use traces back to the admin's decision (AP-8 spirit). The console shows "Allow despite failed checks" (dialog: days + required reason), an
  "Exception until <date>" note in the Compliance column and an "End exception" button.
  Fault found and fixed while testing, mine: the first version called `publishDeviceEvent` as well as `audit()`, so every grant or removal was audited
  twice, once wrongly attributed to the AGENT (`publishDeviceEvent` hard-codes the agent as actor). `audit()` already records the activity entry and the
  audit event, so the extra call was removed; the unit tests caught it. Tests: 6 gate cases (active, lifecycle state, expired, never lets other
  states in, someone else's laptop, no exception audit when compliant) and 4 service cases (grant, refuse non-approved, refuse 0 / 31 days / empty
  reason, remove idempotent); whole tenant suite on the VM: 229 tests, 0 failures. Not tested live in a browser yet.
  Still open: an exception does not end when the laptop's posture becomes compliant (it simply stops mattering); there is no list of all active
  exceptions or reminder before one expires.

- **2026-11-19 -- Platform-level sign-in rule: only an authorised laptop may sign in (new tenant setting, off by default). Tier 3, choices made by the user.**
  Request: besides the per-app "trusted device" rule, refuse the sign-in itself, at the sign-in screen, with "you are not authorised to sign in from
  this device". Choices put to the user and answered: applies to everyone EXCEPT administrators; "authorised" = approved AND compliant (the same rule
  as apps, so an admin's compliance exception counts); the refusal states the specific reason.
  Where it lives: the decision is made by iam-tenant-svc (`DeviceLoginRuleService`, which owns the tenant switch and the device state; it reuses the new
  `TrustedDeviceGate.evaluateDevice`, so apps and sign-in cannot disagree) and ENFORCED in iam-auth-svc `AuthService.login`, after the password,
  policy and second factor, and after the device proof is verified, but before any session exists (AP-1 one engine, AP-3 no session without the
  platform deciding). It is asked over `POST /internal/login-device-check` (InternalOnlyFilter: 404 through the public proxy). It FAILS CLOSED: if the
  check cannot be made the sign-in is refused with DEVICE_CHECK_UNAVAILABLE, never let through. Refusals are audited by auth-svc as `auth.login_denied`
  (reason `device not authorised: ...`); a sign-in let in only because of a compliance exception is audited as `auth.login.allowed_compliance_exception`.
  The switch: table `tenant_device_login_rule` (V15, no row = off), `GET/PUT /api/v1/endpoint/login-rule` (tenant admin; changes audited as
  `tenant.device_login_rule.enabled/disabled`), a checkbox on Endpoint Security whose confirmation lists the active users who own no approved laptop and
  would be refused. Four new `AuthErrorCode`s: DEVICE_REQUIRED, DEVICE_NOT_APPROVED, DEVICE_NON_COMPLIANT, DEVICE_CHECK_UNAVAILABLE, each with its own
  portal message.
  The trap and how it is closed: a new laptop has to sign in once to register itself, so the rule cannot apply to that one sign-in. A flag on the public
  login request, or letting the portal's enrollment sign-in set the normal SSO cookie, would let anyone skip the rule: /device-enroll can be opened by
  anyone, and a signed-in browser is a working sign-in. So the enrollment sign-in uses a separate route, `POST /internal/login/enrollment` on auth-svc
  (service-to-service only, the same InternalOnlyFilter idea; `enforceDeviceRule=false` is a method parameter, not a request field), and the portal
  (`finishEnrollmentSignIn`) uses that session only server-side to start the enrollment, then logs it out, and NEVER sets the SSO cookie. The only
  thing such a sign-in can produce is a laptop of the user's own that waits for approval. Audited as `auth.login.enrollment_signin`.
  Checked live from the internet: `/internal/login/enrollment` and `/internal/login-device-check` both answer 404; `/api/v1/login` exists. From inside
  the network the device check answers allowed for a tenant with the rule off, and the enrollment route exists.
  Tests: tenant `DeviceLoginRuleServiceTest` (admin exempt, every refusal reason, exception, expired exception, switch audit), auth `AuthServiceTest`
  additions (refusal issues no session, each code, unknown code, fail closed on error and on an open breaker, who/role/device asked about, enrollment
  skips the rule and is audited, bad password never reaches the rule) and `InternalOnlyFilterTest`, portal `deviceEnroll.test.ts` and message tests.
  Whole suites on the VM: tenant 243 and auth 43, 0 failures; portal 80 passed (run locally). NOT yet tried live in a browser, and the rule has never been switched on.
  Known limits: (1) admin "Switch user" (ImpersonateController) issues a session for another user without a sign-in, so it is not subject to this rule
  (apps still apply their own); (2) with the rule on, a user whose only laptop is still pending cannot sign in until it is approved, by design; (3) the
  agent's enrollment link opened with the old 0.3.3 agent can still reuse an existing browser session (the `prompt=login` change still needs a new MSI);
  (4) see the follow-up entry below: the rule is now also asked at the password step.

- **2026-11-19 -- Sign-in rule: refuse at the password step, not after the code (follow-up to the entry above). Tier 3, requested by the user.**
  The first version asked the rule only inside `login()`, i.e. after the second factor, so a person on an unauthorised laptop typed a code (or was sent a
  push on their phone) and only then heard "not authorised". Now `AuthService.precheck` asks the same rule right after the password and the location policy,
  before any second-factor step or authenticator-QR offer, and `login()` asks again (that remains the decision that counts; precheck is the early answer).
  The portal asks the agent for a proof at the password step (`proofForPasswordStep`, same safe-by-default behaviour: no agent or any error means no proof) and
  sends it with the precheck; the final submit gets its own proof because a challenge is single use. The agent's laptop-registration sign-in is exempt at this
  step too, through `POST /internal/login/precheck-enrollment` (service-to-service only, `enforceDeviceRule=false` is a method parameter). Checked: both internal
  routes answer 404 from the internet, the public precheck exists, and the internal route exists from inside the network.
  Not done on purpose: refusing at the EMAIL step. That would tell anyone, with no password, whether an email belongs to a user and whether that user is an
  administrator (admins are exempt) -- a user-enumeration leak. At the password step the person has already proved they know the password, and precheck already
  reveals more than this (whether a code is needed). Accepted trade-off: someone who knows only the password can learn that this laptop would be refused.
  Side effect that is also a gain: no push notification is sent to the real user's phone for a sign-in that is going to be refused.
  A user with no authenticator yet and an unauthorised laptop is refused before being offered the QR; they register a laptop through the agent first.
  Tests: five new `AuthServiceTest` cases (refused before any 2FA step, fails closed, asked about the verified device and role and lets an authorised laptop on,
  the enrollment precheck skips the rule, a wrong password never reaches it). Auth 48 tests, 0 failures on the VM; portal 80 passed, type-check clean.
  Not yet tried live in a browser.

- **2026-11-19 -- Endpoint agent 0.3.4: block personal Microsoft (Outlook) sign-in on the web in Chrome and Edge (spec 8.2, P1-24 partial). Tier 3, requested by the user.**
  Reported: signing in to Outlook on the web with a personal Outlook account was not restricted. Checked first: the agent was running and
  Chrome/Edge both had the correct `RestrictSigninToPattern` (and Chrome `AllowedDomainsForApps`), so nothing was broken. Those two settings only
  govern signing in to the BROWSER profile, plus a Google-only header for Google sites; Edge has no Microsoft counterpart, and the proper Microsoft
  control (Entra tenant restrictions, spec 8.2) needs an Entra tenant, which the owner had already decided to skip. The spec's stated fallback is
  "documented browser/domain controls" at lower assurance. The user chose that fallback.
  What it does: when the identity restriction is on (allowed domains set), the agent adds `login.live.com`, `outlook.live.com`, `account.live.com`
  and `signup.live.com` to each browser's `URLBlocklist` (Chrome `HKLM\SOFTWARE\Policies\Google\Chrome\URLBlocklist`, Edge `...\Microsoft\Edge\URLBlocklist`).
  The browsers' own enterprise policy, no traffic inspection (AP-7). Work and school accounts sign in at login.microsoftonline.com and are not
  listed (a unit test guards that). Skipped when an allowed domain is outlook.com, hotmail.com, live.com or msn.com (the admin allowed it on purpose).
  Applied at every service start, like the other browser policy; the events are 1012 (applied) and 1013 (failed).
  Safe with other tools: a block list is numbered values ("1","2",...) that a company's own group policy may share, and a browser stops reading it at
  the first gap. So `RegistryBrowserPolicy::merge_url_blocklist` READS the list, keeps every entry that is not ours (`merge_block_list`, pure and
  unit-tested: order kept, case-insensitive, no duplicates, idempotent), appends ours and writes it back as 1..N, deleting numbers beyond the end. This is the one
  place the agent reads the browser policy key; the doc comment that said it never reads was updated.
  Limits: lower assurance by design (a URL block can be dodged by a browser or profile the policy does not reach, private windows are covered by the
  policy but other browsers are not); it also stops personal Outlook, OneDrive and Xbox sign-in pages in those two browsers on enrolled laptops;
  turning the feature off does not remove the entries (same as the existing sign-in restriction, which has never cleaned up either); Firefox, Safari and
  Entra tenant restrictions remain undone.
  Tests: 10 new agent-core tests (block lists, work sign-in never blocked, allowed personal domain skips it, merge keeps others / no duplicates /
  idempotent); `cargo test --workspace` 170 passed on the VM and the Windows executable built. NOT yet tried live: the registry reading and writing and
  the blocking itself still need the 0.3.4 installer put on a laptop, and Edge/Chrome restarted.

- **2026-11-19 -- Central Admin Console switch for the personal Microsoft sign-in block (agent 0.3.5, platform V16). Tier 3, requested by the user; default OFF chosen by the user.**
  Request: block and unblock personal Outlook sign-in from one central place instead of by installing a different agent. Agreed order: prove 0.3.4
  on the laptop first (done: the block list was written correctly to both browsers, fresh Edge and Chrome profiles blocked outlook.live.com and let a
  control site through, and Edge's `edge://policy` listed it), then build the switch.
  How the setting reaches a laptop: a per-tenant row (`tenant_browser_controls`, V16; none means off), `GET/PUT /api/v1/endpoint/browser-controls`
  (tenant admin, audited as `tenant.browser_controls.personal_microsoft_block.enabled/disabled`, changes only), and in every device policy a
  `browserControls {blockPersonalMicrosoft, signature}` block. It is signed ON ITS OWN, with the same transit key, over
  `iam-browser-controls-v1|tenant|device|policyId|policyVersion|issuedAt|expiresAt|flag` (golden vector pinned in Kotlin and in Rust), so the existing policy
  signature (`iam-device-policy-v1`) is byte-for-byte unchanged and every installed agent keeps verifying it; older agents ignore the extra JSON. Bound to the
  policy it travels with, so it cannot be replayed onto another device, policy version or issue time. A Kotlin test proves the policy string is identical with
  the switch on and off.
  Agent 0.3.5: `verify_policy` checks the second signature and returns Absent / Verified / Invalid. The raw claim is dropped before the policy is cached, so
  nothing unverified is stored or acted on. The sync loop acts only when the verified setting differs from what it last applied (and once after each start, so an
  upgrade from 0.3.4 ends up consistent: "off" takes 0.3.4's block away), only for a policy the cache actually accepted (a rolled-back or expired one cannot
  switch anything), reports a failure and retries next tick, and reports a bad signature once. No controls at all (an older platform) means no change.
  `remove_from_block_list` is the mirror of `merge_block_list`; the registry writer is one shared function for add and remove, and a remove never creates a list
  that does not exist. Events: 1012 applied, 1013 failed, 1014 removed, 1015 setting ignored.
  Changed on purpose: 0.3.4 blocked whenever allowed domains were set and skipped when an allowed domain was a personal Microsoft one; 0.3.5 has no such local rule,
  the central choice is the only one. The console shows how many enrolled laptops still run an agent older than 0.3.5, since they ignore the switch.
  Limits: removal takes off any entry equal to one of ours, even if a company's own policy listed the same host (merging cannot tell whose it was); a browser that
  is already open may need a restart or Reload policies to notice; lower assurance (a URL block in Chrome and Edge only); Edge's own sign-in dialog is a
  browser-owned window the URL list does not filter (seen live), and there the profile sign-in restriction decides (the owner reported that test as successful).
  Tests: agent-core 188 (18 new: verifier incl. tampered / replayed / other-key / malformed controls, removal, and the sync behaviour above), tenant 256,
  console version-comparison tests; `cargo test --workspace` and the Windows build ran on the VM. Not yet tried live: switching it from the console and a laptop
  on 0.3.5 applying and removing the block. (A console test in `tenant.test.ts` fails on a clean checkout of the previous commit too; unrelated, left alone.)
