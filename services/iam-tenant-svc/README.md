# iam-tenant-svc

Service 2 in `BUILD_PLAN.md`'s build order — owns tenant records. No outbound
calls to any other service.

## Contract

`iam-platform-docs/contracts/iam-tenant-svc.yaml` — `POST /api/v1/tenants`,
`GET /api/v1/tenants/{id}`, plus OIDC client registration (added 2026-09-17
for Service 11): `POST/GET /api/v1/oidc-clients`,
`POST /api/v1/oidc-clients/{id}/verify-secret`.

## OIDC client registration

A registered client's `id` doubles as its OIDC `client_id`. The secret is
returned in plaintext exactly once, at creation, and only its Argon2 hash
(no pepper -- it's already 256 bits of `SecureRandom`, not a human-chosen
password) is stored. `verify-secret` is enumeration-safe: "no such client"
and "wrong secret" return the identical response shape, same reasoning as
`iam-identity-svc`'s `verify-password`.

## Callers / callees

- **Called by:** future services needing to validate tenant existence
  (`iam-identity-svc`, Service 4) or per-tenant client registration
  (`iam-oidcprovider-svc`, Service 11) — via `iam-service-kit`'s
  Resilience4j-wrapped HTTP client, per the published contract only.
- **Calls:** nothing.
- **Produces:** `tenant.created` to `audit-events` on tenant creation.

## Data

Own Postgres database (`tenant_db`), one table `tenants`, Flyway-managed.
`subdomain` is unique (enforced at the DB and checked before insert) — this is
what `<subdomain>.platform.com` login (BRD FR-6.2) resolves against later.

## Build / run

```
./gradlew build
./gradlew bootRun
```

Requires `iam-platform-docs/docker-compose.yml`'s Postgres + Kafka + OpenBao
running, and the `tenant_db` database to exist (see that repo's
`infra/postgres-init/`).

## TEST GATE (BUILD_PLAN.md §6)

Create a tenant → row in `tenant_db.tenants` → matching `tenant.created` row
in `iam-audit-svc`'s `audit_db.audit_events` (same `correlationId` on both).
Duplicate subdomain → `409`, no row, no audit event. Unknown ID → `404`.
Invalid subdomain shape → `400`.
