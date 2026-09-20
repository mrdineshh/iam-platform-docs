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
