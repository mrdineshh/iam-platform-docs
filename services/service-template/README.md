# service-template

Copy-paste starting point for every service in `BUILD_PLAN.md` Section 6's
build order (Service 0 — Shared Foundation deliverable). Boots a minimal
Spring Boot app with:

- Actuator health endpoints (`/actuator/health/liveness`, `/actuator/health/readiness`)
- `iam-service-kit` wired in via Gradle composite build — correlation-ID
  filter, audit publisher, OpenBao client all auto-configured
- OpenTelemetry auto-instrumentation exporting to Jaeger
- Kafka producer configured with string serializers, pointed at the shared
  `audit-events` topic

## Using this for a new service

1. Copy this folder to `../iam-<name>-svc`.
2. Rename the root package (`com.iamplatform.template` → `com.iamplatform.<name>`),
   `settings.gradle.kts`'s `rootProject.name`, and `spring.application.name`
   in `application.yml`.
3. Add the service's own domain code, controllers, repository, and DB
   migrations — none of that belongs in `iam-service-kit`.
4. Write the OpenAPI contract in `iam-platform-docs/contracts/<service>.yaml`
   *before* the implementation, per the Working Agreement.

## Build / run

```
./gradlew build
./gradlew bootRun
```

Requires the shared infra from `iam-platform-docs/docker-compose.yml`
(`docker compose up -d`) for Kafka/OpenBao to actually be reachable — the app
itself boots without them (Kafka producer creation is lazy; OpenBao/HTTP
clients aren't called until something exercises them).

## Status

Generated as part of Service 0. Not yet compiled against a local JDK/Gradle
install in this environment — open in IntelliJ (which bundles its own JDK/Gradle
support) or install a JDK 21 + run `./gradlew build` to verify.
