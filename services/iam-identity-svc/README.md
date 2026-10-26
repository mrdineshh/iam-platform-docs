# iam-identity-svc

Service 4 in `BUILD_PLAN.md`'s build order — owns user records and (later)
JIT provisioning. First service in the build order with a real outbound
dependency.

## Contract

`iam-platform-docs/contracts/iam-identity-svc.yaml` —
`POST /api/v1/users`, `GET /api/v1/users/{id}`,
`PATCH /api/v1/users/{id}/status`, `PATCH /api/v1/users/{id}/password`,
`POST /api/v1/users/verify-password`.

## Password storage (added 2026-09-13 for Service 7)

Argon2id (m=19456 KiB, t=2, p=1) + a platform-wide pepper, get-or-created in
OpenBao KV v2 on first use (MVP-TEMPORARY -- see `docs/DECISIONS.md`,
Service 7 entry, for why this isn't per-tenant via Transit yet).
`verify-password` always returns `200`; `valid:false` with no `userId`/
`status` is deliberately identical for "no such user" and "wrong password" --
never gives a caller a way to enumerate which emails exist. Never returns
the hash. Only `iam-auth-svc` is meant to call it.

## Callers / callees

- **Calls:** `iam-tenant-svc` (`GET /api/v1/tenants/{id}`) to validate a
  tenant exists before creating a user -- only through its published
  contract, never its database. Resilience4j-wrapped: circuit breaker trips
  after 5 buffered calls at a 50% failure rate, retry up to 5 attempts with
  exponential backoff on genuine failures, but never retries a business 404
  or a `CallNotPermittedException` (see `docs/DECISIONS.md` for the two real
  bugs found getting this right).
- **Called by:** future services needing to validate/patch a user
  (`iam-auth-svc`, `iam-directory-svc`) via the same resilience pattern.
- **Produces:** `identity.created`, `identity.status_changed` to
  `audit-events`.

## Data

Own Postgres database (`identity_db`), one table `users`, Flyway-managed.
`(tenant_id, email)` is unique.

## Build / run

```
./gradlew build
./gradlew bootRun
```

Requires `iam-platform-docs/docker-compose.yml`'s Postgres + Kafka + OpenBao
+ `iam-tenant-svc` running, and the `identity_db` database to exist.

## TEST GATE (BUILD_PLAN.md §6)

Create a user under a valid tenant -> `201` + `identity.created` audit event.
Create under a nonexistent tenant -> `404`, nothing created. Duplicate email
in the same tenant -> `409`. `PATCH .../status` -> `200` +
`identity.status_changed`. Killing `iam-tenant-svc` mid-test: first call
fails bounded (~10s), circuit breaker opens, subsequent calls fail in
~150ms instead of hanging; restarting the dependency and waiting out the
cooldown recovers cleanly.
