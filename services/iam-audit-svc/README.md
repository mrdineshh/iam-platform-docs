# iam-audit-svc

Service 1 in `BUILD_PLAN.md`'s build order — the audit event sink. Owns audit
event storage; has no outbound calls to any other service, which is why it's
safe to build first (nothing else needs to exist for it to work).

## Contract

No OpenAPI contract — this service exposes no synchronous REST API for other
services to call (see `iam-platform-docs/docs/DECISIONS.md`, Service 1 entry).
Its only interface is the Kafka message schema at
`iam-platform-docs/contracts/audit-events.avsc`.

## Callers / callees

- **Consumes:** `audit-events` (every other service publishes here)
- **Produces:** `audit-events-dlq` (messages that fail processing after 5
  retries with exponential backoff — never silently dropped, Guardrails §2)
- **Calls:** nothing. No other service, no OpenBao secret currently needed
  beyond what's wired by default from `iam-service-kit`.

## Data

Own Postgres database (`audit_db`), one table `audit_events`, Flyway-managed
(`src/main/resources/db/migration`). `event_id` is the primary key and the
idempotency key: a redelivered message with an already-seen `event_id` is
logged and skipped, not double-written or treated as a failure.

## Build / run

```
./gradlew build
./gradlew bootRun
```

Requires `iam-platform-docs/docker-compose.yml`'s Postgres + Kafka running,
and the `audit_db` database to exist (see that repo's `infra/postgres-init/`).

## TEST GATE (BUILD_PLAN.md §6)

Publish a raw event to `audit-events` via `kafka-console-producer` → a row
appears in `audit_db.audit_events` within seconds.
