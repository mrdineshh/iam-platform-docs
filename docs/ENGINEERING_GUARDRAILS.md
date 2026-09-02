# Engineering Guardrails & Autonomous Decision Framework

This document exists because Claude Code is building this platform with minimal
human-in-the-loop review per step. It defines what can be decided autonomously,
what must be flagged before proceeding, the error-handling standard every module
must follow, the audit-event shape every module must emit, and the Definition of
Done every module must meet before it's considered complete.

This applies **in addition to** `/CLAUDE.md` (architecture principles, tech stack,
exclusions) and `/docs/BRD.md` (the requirements themselves) — read all three.

---

## 1. Autonomy Tiers

Every implementation decision falls into one of three tiers. When unsure which
tier a decision belongs to, treat it as Tier 3.

### Tier 1 — Fully autonomous, no flag needed
Decide and proceed without pausing or logging the reasoning:
- Internal code style, naming, file/function organization within a module
- Choice of internal helper libraries *within* the already-approved tech stack
  (e.g., which JSON library within the Kotlin/Spring ecosystem)
- Test structure and organization
- Non-security-relevant business logic implementation details (e.g., how a
  report's data is aggregated for display, as long as the underlying data source
  and access control are correct)

### Tier 2 — Proceed, but record the decision
Implement it, but append a one-line entry to `/docs/DECISIONS.md` (create if it
doesn't exist) so a human can review the trail later without having to re-derive
it from the diff:
- Adding a new database field/table within a module that doesn't change security
  or tenant-isolation semantics
- Adding a new REST endpoint within a module's already-approved scope (e.g., a
  new list/filter endpoint for data already covered by that module's FR-x.x)
- Internal service-to-service boundaries within a single module
- Choice of a specific library version or minor supporting library not
  explicitly named in `/CLAUDE.md`'s tech stack table

Format for `/docs/DECISIONS.md` entries: `[module] [date] — decision — one-line
rationale — FR/AP reference if applicable`

### Tier 3 — Stop and flag before proceeding. Do not guess.
Surface these explicitly (in the session, and as a flagged item in
`/docs/OPEN_QUESTIONS.md`) rather than making a plausible-looking assumption:
- Anything that touches, reinterprets, or could weaken **AP-1 through AP-8**
  (`/CLAUDE.md` Section: Non-Negotiable Architecture Principles)
- Any cryptographic algorithm, key size, or key-storage decision (device trust
  certs, session tokens, password hashing algorithm/parameters)
- Any change to break-glass access, agent uninstall authorization, or device
  trust logic — these are the highest-consequence modules in the system
- Any behavior that isn't traceable to a specific `FR-x.x`/`NFR-x.x` in the BRD
  — if you find yourself implementing something the BRD doesn't ask for, stop
  and confirm it's actually needed rather than building it speculatively
- Any new external third-party dependency not already named in `/CLAUDE.md`'s
  tech stack table — including a "lighter" or "more popular" alternative to one
  already chosen
- Anything that would change data retention, audit scope, or compliance posture
  (Section 7 of the BRD)
- Any relaxation of a Tier-3-adjacent test (e.g., skipping a negative-case test
  "to unblock" a module) — do not weaken test coverage to hit a deadline

---

## 2. Standard Error Handling & Resilience (applies to every module)

Do not invent a different pattern per module — use this one everywhere so
behavior is predictable across a polyglot stack:

- **Retries:** exponential backoff with jitter, capped at a configurable max
  attempt count (default 5). Any retried *mutating* operation (SCIM sync,
  webhook delivery, agent command dispatch) must be idempotent — carry or
  generate an idempotency key so a retry can't double-apply an effect.
- **Circuit breakers:** required on every call to a downstream dependency
  outside the platform's own control — AD/Entra/ADFS connectors, SCIM
  endpoints, the HIBP-style breached-password API, the IP-geolocation service.
  Trip on a configurable consecutive-failure threshold (default 5); half-open
  retry after a configurable cool-down (default 30s).
- **Timeouts:** explicit and configurable per external dependency. No unbounded
  waits anywhere in a request path, especially the PEP (AP-2) — a slow
  downstream dependency must never be able to stall policy enforcement
  indefinitely.
- **Dead-letter handling:** any Kafka consumer that fails to process a message
  after exhausting retries must route it to a dead-letter topic, not drop it
  silently. Dead-letter volume must be observable (Prometheus metric).
- **Error classification for logging:** every error is one of:
  - *Security-relevant* (auth failure, policy violation, break-glass use,
    uninstall attempt) → must emit an audit log event per Section 3 below, in
    addition to normal application logging.
  - *Operational* (transient network failure, retry exhausted, downstream
    timeout) → application logs only (Loki), not the audit log.
  Do not conflate the two — security-relevant events must never depend on the
  operational logging pipeline's retention/availability, since audit retention
  (FR-11.2) has different guarantees than ops log retention.
- **Graceful degradation:** if a non-critical downstream dependency is down
  (e.g., the IP-geolocation service), the platform should fail toward the
  safer default for that policy (e.g., treat an unresolvable IP as
  higher-risk, triggering adaptive step-up, not as a free pass) rather than
  failing open.

---

## 3. Minimum Audit Event Schema (every module, every security-relevant action)

Per FR-11.1, every module that performs a security-relevant action must emit an
audit event with at least these fields — a module-specific `SPEC.md` can add
fields but must not omit these:

| Field | Description |
|---|---|
| `event_id` | Unique identifier for this event |
| `timestamp` | UTC, millisecond precision |
| `tenant_id` | Tenant the event occurred under |
| `actor_type` | `user` \| `admin` \| `system` \| `agent` |
| `actor_id` | Identifier of the actor (user/admin ID, or system/agent identifier) |
| `action` | Machine-readable action name (e.g., `session.terminated`, `agent.uninstall_authorized`, `policy.updated`) |
| `target_type` / `target_id` | What the action was performed on (e.g., `device`/`device-id`, `policy`/`policy-id`) |
| `result` | `success` \| `failure` \| `denied` |
| `reason` | Human-readable reason, especially for `failure`/`denied` (e.g., which policy/hard-cap triggered a denial) |
| `source_ip`, `geo`, `device_id` | Context of the request, where applicable |
| `policy_scope_applied` | Which level resolved the decision — Tenant / OU / User (AP-4) — for anything policy-evaluation-related |

This schema must be agreed as part of module 1 (Directory & Auth Policy Engine)
since audit emission is a cross-cutting concern most other modules depend on.

---

## 4. Definition of Done (every module)

A module is not complete until all of the following are true:

- [ ] Every `FR-x.x` assigned to this module in the BRD is implemented and
      traceable (comment or commit reference back to the FR number)
- [ ] Unit + integration tests exist; security-sensitive modules additionally
      have explicit **negative/violation-path tests** (e.g., "session
      terminates when IP changes mid-session," not just "session persists when
      IP stays the same")
- [ ] API spec (OpenAPI/Swagger or equivalent) is generated/committed and
      matches the actual implementation
- [ ] DB migrations are versioned and reversible
- [ ] Every state-changing action in the module emits an audit event matching
      Section 3's schema
- [ ] No hardcoded secrets — all secrets sourced from OpenBao
- [ ] Error handling follows Section 2 (retries, circuit breakers, timeouts,
      dead-letter handling as applicable)
- [ ] For PEP-adjacent code paths specifically: a latency/load check confirms
      the continuous policy re-evaluation (AP-2) doesn't introduce unacceptable
      per-request overhead
- [ ] A module README exists with: schema diagram, endpoint list, and a
      one-paragraph description of what the module does and which FRs it covers
- [ ] Every Tier-3 decision encountered during the build was flagged and
      resolved (not silently assumed) — check `/docs/OPEN_QUESTIONS.md` is
      empty for this module before marking it done

---

## 5. Required Contents of Every Per-Module SPEC.md

When running the interview-then-spec step for a module (see `/CLAUDE.md`
"Workflow For Each Module"), the resulting `SPEC.md` must include all of the
following — treat a spec missing any of these as incomplete:

1. **Data schema** — every table/collection, field name, type, constraints,
   nullability, and which fields are tenant-configurable vs. system-fixed
2. **API surface** — for every endpoint: HTTP method, path, purpose, request
   schema, response schema, auth/permission required, and which `FR-x.x` it
   implements
3. **Audit events emitted** — which actions in this module emit an audit event,
   using the Section 3 schema plus any module-specific fields
4. **Error handling specifics** — any deviation from or addition to Section 2's
   standard pattern, and why
5. **Success criteria** — module-specific acceptance criteria beyond the
   generic Definition of Done in Section 4
6. **Open questions / Tier-3 flags** — anything the interview surfaced that
   needs explicit human confirmation before or during build
