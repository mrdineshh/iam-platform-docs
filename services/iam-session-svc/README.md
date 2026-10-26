# iam-session-svc

Service 6 in `BUILD_PLAN.md`'s build order. Owns session lifecycle, backed by
Valkey with opaque tokens (never JWTs), so killing a session mid-flight
(AP-2) is a direct delete, not a revocation workaround.

## Contract

`iam-platform-docs/contracts/iam-session-svc.yaml`:
`POST /api/v1/sessions`, `GET /api/v1/sessions`, `DELETE /api/v1/sessions?reason=...`.
The token travels only in the `X-Session-Token` header for `GET`/`DELETE`,
never in the URL -- changed 2026-09-13 (see docs/DECISIONS.md) because a path
parameter risks the raw token being recorded as a trace span attribute.

## Callers / callees

- **Calls:** nothing. No other service, no database.
- **Called by:** `iam-auth-svc` (Service 7) issues sessions (per AP-1, the only
  intended issuer). `iam-enforcement-svc` (Service 10) validates and
  terminates them. Caller restriction isn't enforced yet; that comes with
  deviation D2's inter-service auth.
- **Produces:** `session.issued` and `session.terminated` to `audit-events`.

## Storage

Valkey only. Each session is a JSON record under `session:<sha256(token)>`
with a TTL equal to the session lifetime (`iam.session.ttl`, default `8h`).
The raw token is never used as a key, so a dump of the session keyspace
doesn't yield usable bearer tokens.

## Behavior worth knowing

- **Idempotency-Key** (BUILD_PLAN.md §1): a retried `POST` with the same
  key, tenant, and user within `iam.session.idempotency-window` (default
  `10m`) returns the original session with `Idempotent-Replayed: true`.
  It does not issue a second session or publish a second audit event.
  Reusing a key for a different user returns `409`.
- **DELETE is atomic** (GETDEL), so concurrent terminations publish exactly
  one `session.terminated`. A second DELETE returns `404`.
- **Valkey down** returns `503` within about 2s. The command and connect
  timeouts are explicit, not Lettuce's 60s default. Health reports `DOWN`,
  and the service recovers on its own when Valkey returns.
- The token is never in the URL, so no path redaction is needed in error
  bodies; a missing `X-Session-Token` header returns `400`.

## Build / run

```
./gradlew build
./gradlew bootRun
```

Requires `iam-platform-docs/docker-compose.yml`'s Valkey + Kafka + OpenBao.

## TEST GATE (BUILD_PLAN.md §6)

Issue a session, validate it (`200`), delete it (`204`), then validate
again (`404`). Each step's audit event must appear in `iam-audit-svc`'s
database with the caller's correlation ID.
