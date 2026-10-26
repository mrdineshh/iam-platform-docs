# iam-service-kit

Shared **technical** infrastructure for every Kotlin/Spring Boot service in
the IAM platform MVP (`BUILD_PLAN.md` Section 4.5, "Service 0 — Shared
foundation"). Consumed via Gradle composite build (`includeBuild`), not a
published artifact — see `/docs/DECISIONS.md` in `iam-platform-docs`.

**Never allowed here:** `User`, `Policy`, `Session`, or any other domain
model. Each service defines its own DTOs from its own OpenAPI contract;
duplication across services is the price of independence, not a bug.

## What's in here

| Package | Provides |
|---|---|
| `audit` | `AuditEvent`/`ActorType`/`AuditResult` (the shape every service publishes to Kafka), `AuditPublisher` interface, `KafkaAuditPublisher` implementation |
| `correlation` | `CorrelationId` holder + `CorrelationIdFilter` — assigns/propagates `X-Correlation-Id` on every inbound request and makes it available for outbound calls and audit events |
| `http` | `ResilientHttpClient` — Resilience4j circuit-breaker + retry wrapper around Spring's `RestClient`, with correlation-ID propagation baked in; `resilientRestClientBuilder` for explicit connect/read timeouts |
| `vault` | `OpenBaoClient` — reads secrets from OpenBao's KV v2 engine; no service should hardcode a secret |
| `error` | `ErrorResponse` — the one error body shape every service returns |
| `autoconfigure` | `ServiceKitAutoConfiguration` — wires the above as Spring beans automatically for any service that depends on this module |

## How a service consumes this

In the service's `settings.gradle.kts`:

```kotlin
includeBuild("../iam-service-kit")
```

In the service's `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.iamplatform:iam-service-kit")
}
```

No further wiring needed — `ServiceKitAutoConfiguration` registers the
correlation filter, `AuditPublisher`, and `OpenBaoClient` beans automatically.
The service must still supply `spring.kafka.bootstrap-servers` and
`iam.openbao.address` / `iam.openbao.token` via its own `application.yml` /
environment, per 12-factor config.

## Build

```
./gradlew build
```

No Postgres/Kafka/OpenBao required to build or run this module's own tests —
it has no outbound calls in its test suite. Live wiring is proven when a real
service (starting with `iam-audit-svc`) depends on it.

## Status

Built as part of Service 0 (Shared Foundation) per `BUILD_PLAN.md`. Not yet
compiled against a local JDK/Gradle install in this environment — see the
umbrella repo's session notes for what's still unverified.
