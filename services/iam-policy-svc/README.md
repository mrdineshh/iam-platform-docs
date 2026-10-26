# iam-policy-svc

Service 5 in `BUILD_PLAN.md`'s build order — the merge-with-hard-cap policy
engine (AP-4). Pure logic + storage, no outbound calls.

## Contract

`iam-platform-docs/contracts/iam-policy-svc.yaml` —
`PUT /api/v1/policies`, `POST /api/v1/evaluate`.

## MVP-TEMPORARY scope

Only the country allow-list/block-list attribute pair is implemented -- the
one policy dimension the MVP demo flow (`BUILD_PLAN.md` Section 2) actually
exercises via `iam-geo-svc`. BRD FR-4.1's IP-range and device-trust
attributes are deferred. `PolicyEvaluator` (the merge/hard-cap resolver) is
attribute-generic, so adding a new attribute later is additive, not a
redesign.

## Merge rule (AP-4 / BRD FR-4.2)

Per attribute, independently:
1. If the TENANT record marks the attribute a hard-cap, its value wins
   unconditionally -- OU/USER values for that attribute are ignored entirely
   (not merged with).
2. Otherwise: USER's value if defined, else OU's, else TENANT's, else no
   restriction.

Block-list is checked before allow-list, so an explicit block always wins
over an allow-list entry for the same country.

## Callers / callees

- **Calls:** nothing.
- **Called by:** `iam-auth-svc` (login-time check), `iam-enforcement-svc`
  (continuous PEP re-check).
- **Produces:** `policy.updated` to `audit-events` on every `PUT`.
  `POST /api/v1/evaluate` does **not** publish an audit event per call (hot
  path; the caller records the resulting security outcome instead).

## Build / run

```
./gradlew test    # the actual TEST GATE for this service
./gradlew bootRun
```

## TEST GATE (BUILD_PLAN.md §6)

`./gradlew test` — 18 tests: default-allow with no policy configured, plain
tenant allow/block-lists, OU/USER override vs. inherit, hard-cap surviving
an override attempt at every lower level (both attributes), block-beats-allow
precedence, and service-layer validation (`scopeId` required for OU/USER,
hard-cap rejected outside TENANT, upsert not duplicate). Also verified live:
a hard-capped tenant block on a country survives an OU's attempt to add
another blocked country, and `policy.updated` audit events land correctly.
