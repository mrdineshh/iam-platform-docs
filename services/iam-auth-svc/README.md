# iam-auth-svc

Service 7 in `BUILD_PLAN.md`'s build order -- the login orchestrator (AP-1).
Owns no data of its own; pure orchestration. This is the first real
integration checkpoint: one login touches five services under one
correlation ID.

## Contract

`iam-platform-docs/contracts/iam-auth-svc.yaml` -- `POST /api/v1/login`,
`POST /api/v1/logout`.

## Orchestration

```
POST /api/v1/login
  -> iam-identity-svc: POST /api/v1/users/verify-password   (password check)
  -> iam-geo-svc:      GET  /api/v1/resolve                 (location)
  -> iam-policy-svc:   POST /api/v1/evaluate                (allowed?)
  -> iam-session-svc:  POST /api/v1/sessions                (issue)
```

Every call is Resilience4j-wrapped. `iam-geo-svc`/`iam-policy-svc` failures
are caught and folded into a `403` denial (BUILD_PLAN.md Section 4.6: never
fail open -- an unreachable risk gate defaults to closed, not skipped).
`iam-identity-svc`/`iam-session-svc` failures propagate to a `503` -- those
aren't risk gates, they're required infrastructure.

## Callers / callees

- **Calls:** `iam-identity-svc`, `iam-geo-svc`, `iam-policy-svc`,
  `iam-session-svc` -- only through their published contracts.
- **Called by:** `iam-login-portal` (Service 13, not yet built).
- **Produces:** `auth.login_success`, `auth.login_failure`,
  `auth.login_denied` to `audit-events`. Does not publish for logout --
  `iam-session-svc` already publishes `session.terminated` for that.

## Behavior worth knowing

- `POST /api/v1/login`'s `sourceIp` is client-supplied (MVP-TEMPORARY --
  there's no PEP/gateway yet to derive it server-side; see
  `docs/DECISIONS.md`).
- Session issuance uses `Idempotency-Key: <correlationId>` so a
  Resilience4j retry after a timeout can't issue two sessions for one login.
- `POST /api/v1/logout` takes the token via `X-Session-Token` header, never
  in the URL (matches `iam-session-svc`'s own contract).

## Build / run

```
./gradlew build
./gradlew bootRun
```

Requires `iam-platform-docs/docker-compose.yml`'s full stack: Kafka,
OpenBao, and all of `iam-identity-svc`, `iam-geo-svc`, `iam-policy-svc`,
`iam-session-svc` running.

## TEST GATE (BUILD_PLAN.md §6)

Correct password + allowed location -> `200`, session issued, full trace
across all 5 services visible in Jaeger under one trace ID. Wrong password
-> `401` + `auth.login_failure`. Blocked-country login -> `403` +
`auth.login_denied` naming the policy. Killing `iam-session-svc` mid-test
-> clean bounded `503`, not a hang; recovers on retry once restarted.
