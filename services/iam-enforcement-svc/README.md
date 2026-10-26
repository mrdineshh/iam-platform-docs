# iam-enforcement-svc

Service 10 in `BUILD_PLAN.md`'s build order — the Policy Enforcement Point
(PEP, AP-2). On every protected request, re-validates the session, the
current location, and policy fresh, independent of `iam-auth-svc` (which
only runs once, at login). On a confirmed policy violation, terminates the
session via `iam-session-svc` before responding — the kill is mid-flight,
not eventual.

## Contract

`iam-platform-docs/contracts/iam-enforcement-svc.yaml` —
`POST /api/v1/enforce`, header `X-Session-Token`, body `{sourceIp}`.

BUILD_PLAN.md describes this service's behavior but not an exact endpoint
shape; this contract was designed and confirmed with the product owner
before implementation (see `docs/DECISIONS.md`, Service 10 entry).

## What's cached, and what never is

Only the **policy decision** (`(tenantId, userId, country) -> allowed`) is
cached in Valkey, 30s TTL, to bound per-request overhead. **Session
validity is never cached** — every call hits `iam-session-svc` fresh,
because caching that would defeat the entire point of continuous
enforcement. The cache key includes `userId`, not just `tenantId`+
`country`, so a user with a more specific OU/USER-scope policy override
(AP-4) never gets served another user's cached tenant-level decision.

## Three denial cases, one response shape

All three return `401`, distinguished only by the `message` field — this
service never fails open (BUILD_PLAN.md Section 4.6):

1. **Unknown/expired/terminated session** — nothing to audit (no
   tenantId/userId can be attributed to an unrecognized token), no
   termination (nothing to terminate).
2. **Location unresolved, or policy-svc unreachable** — audited as
   `enforcement.check_denied`, but the session is **not** terminated. A
   transient dependency outage denies this one check; it doesn't destroy
   the user's whole session over a blip.
3. **Confirmed policy violation** (the real AP-2 case) — the session is
   terminated via `iam-session-svc` (which independently publishes its own
   `session.terminated` event), and this service additionally audits
   `enforcement.violation` with the policy's own reason and scope.

A **successful** (`200 allowed`) check publishes no audit event — matches
`iam-policy-svc`'s own `evaluate` endpoint precedent (Service 5): an
allowed check is the expected, high-frequency default, not itself a
security-relevant event; auditing every one would drown the log.

## No persistent storage

Stateless except for the Valkey policy-decision cache — no Postgres DB,
unlike most other services.

## TEST GATE (BUILD_PLAN.md §6)

A real session (from a real login through `iam-auth-svc`) checked with a
spoofed blocked-country IP → `401`, session immediately terminated (next
`GET` against `iam-session-svc` confirms it's gone), `enforcement.violation`
and `session.terminated` audit events both present. Latency measured
across repeated calls from the same session/country to confirm the Valkey
cache actually reduces per-request overhead (Guardrails Section 4's
PEP-specific Definition-of-Done requirement) — see `docs/DECISIONS.md`.
