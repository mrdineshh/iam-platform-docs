# iam-admin-console — SPEC

BUILD_PLAN.md Service 14. React + Vite SPA. Lets a tenant admin manage
their own tenant's OIDC clients and access policy through a UI instead of
raw curl.

Interviewed and confirmed with product owner before implementation:
1. **Admin auth = real login + a role field** (not a shared static token).
2. **Scope this pass:** tenants (view only, via the existing by-subdomain/
   by-id lookups — no new endpoint needed), OIDC clients (list + create),
   policy (view + edit). User management is explicitly deferred.
3. **Single-tenant scope only** — an admin manages their own tenant, not a
   cross-tenant "platform super admin" view (BRD FR-7.2's Super Admin tier
   is out of scope for this pass).
4. **Policy-write auth retrofit confirmed:** `iam-policy-svc`'s existing
   `PUT /api/v1/policies` (previously unauthenticated) gets the same admin
   check as the new endpoints, not just additive new surface.

---

## 0. Architecture

There is no admin/role concept anywhere in the system today —
`iam-identity-svc`'s `User` model has no `role` field, and BUILD_PLAN.md's
"two fixed roles" deviation (D3) was never actually implemented. This SPEC
introduces the minimum real version of it:

```
iam-identity-svc:
  UserEntity gains `role: UserRole` (ADMIN | USER, default USER)
  CreateUserRequest gains optional `role` (default USER)
  NEW PATCH /api/v1/users/{id}/role -- promotes/demotes a user (bootstraps
    the very first admin, since the console itself can't create one before
    an admin exists to log into it)
  VerifyPasswordResponse and UserResponse both gain `role`

iam-auth-svc:
  LoginResponse gains `role` (read from iam-identity-svc's verify-password
    call, which already runs on every login) -- lets the console branch its
    UI immediately after login. Never trusted as the actual authorization
    decision on its own -- every admin-console-only backend endpoint
    independently re-verifies role itself (below), the same "never trust
    the client" posture as everywhere else in this platform.

iam-tenant-svc / iam-policy-svc:
  Each gets its own small, local SessionClient + IdentityClient (same
  duplicate-per-service pattern already used by iam-auth-svc and
  iam-oidcprovider-svc -- no new shared library code, since this is
  authorization/business logic, not technical infra, and iam-service-kit
  is explicitly restricted to technical infra only per BUILD_PLAN.md
  Section 4.5).
  A new admin-only endpoint (or, for PUT /api/v1/policies, an existing one
  being retrofitted) requires an `X-Session-Token` header, validates it via
  iam-session-svc, requires the session's tenantId to match the tenantId
  being acted on, and requires the session's userId to resolve (via
  iam-identity-svc) to role=ADMIN. Missing header -> 400. Invalid/expired
  session -> 401. Valid session but wrong tenant or role != ADMIN -> 403.

iam-admin-console (new):
  A pure static SPA (no server of its own, per BUILD_PLAN.md's tech
  choice) -- the browser holds the session token (sessionStorage, cleared
  on tab close) and calls iam-auth-svc / iam-tenant-svc / iam-policy-svc
  directly with it. This means, unlike iam-login-portal, this entry point
  CANNOT capture a real client IP server-side (there is no server) --
  sourceIp reverts to client-supplied for this specific login path, the
  same pre-existing gap every service except iam-login-portal already has.
  Documented as a known, inherited limitation of the already-decided
  "React+Vite SPA" tech choice, not a new regression introduced here.
```

### Login flow
1. Console reads `window.location.hostname`, strips the root domain (same
   `?tenant=` dev-mode fallback pattern as iam-login-portal, for local
   Docker Compose with no wildcard DNS) to resolve a subdomain.
2. Calls `GET /api/v1/tenants/by-subdomain/{subdomain}` on iam-tenant-svc
   (existing endpoint, no auth, already built for Service 13) to get
   `tenantId`.
3. Renders a login form; submits directly to `iam-auth-svc POST
   /api/v1/login` from the browser (client-supplied `sourceIp` — see
   above).
4. On success, checks `role` in the response. `role !== "ADMIN"` -> show
   "this account isn't an admin" and stop (client-side UX only — the real
   gate is every subsequent API call's own server-side check).
5. Stores the session token in `sessionStorage`; every subsequent API call
   attaches it as `X-Session-Token`.
6. TOTP/push second factor: same combined-form UX as iam-login-portal
   (Section 2 of that SPEC) — reused here since it's the same underlying
   `/login` contract shape.

---

## 1. Backend contract changes

### 1.1 `iam-identity-svc`
- `UserEntity` / `users` table: new `role` column, `VARCHAR(16)`, default
  `'USER'`, not null. Flyway migration, reversible (drop column).
- `CreateUserRequest`: new optional `role` (`ADMIN`|`USER`, default `USER`
  if omitted).
- `VerifyPasswordResponse`, `UserResponse`: both gain `role`.
- **New:** `PATCH /api/v1/users/{id}/role` — `{role: ADMIN|USER}` ->
  `200 UserResponse`. Publishes `identity.role_changed` (security-relevant
  — Guardrails §3 schema, `reason` = `"$previousRole -> $newRole"`). `404`
  if unknown user. **No auth on this endpoint in this pass** (bootstrapping
  problem: the very first admin has to be promoted by direct API call
  before any admin session can exist to protect it with) — flagged as a
  known gap, not silently left undocumented; see Section 6.

### 1.2 `iam-auth-svc`
- `LoginResponse`: new `role` field, read straight through from
  `iam-identity-svc`'s `verify-password` response (already called on every
  login — no new outbound call added).

### 1.3 `iam-tenant-svc`
- **New:** `GET /api/v1/oidc-clients?tenantId={tenantId}` — list all OIDC
  clients for a tenant (public info only, never secrets). Requires
  `X-Session-Token`; 400/401/403 per Section 0's admin-check rule; 200
  with an array (possibly empty).
- No changes to existing endpoints (`POST /tenants`, `GET /tenants/{id}`,
  `GET /tenants/by-subdomain/{subdomain}`, `POST /oidc-clients`,
  `GET /oidc-clients/{id}`, `POST /oidc-clients/{id}/verify-secret`) — all
  stay exactly as published, no auth retrofitted onto them in this pass
  (only the new list endpoint gets the check).

### 1.4 `iam-policy-svc`
- **New:** `GET /api/v1/policies?tenantId=&scope=&scopeId=` — fetch the
  raw stored policy at an exact scope (not the merged/evaluated result;
  mirrors `PUT`'s request shape). `scopeId` required for `OU`/`USER`,
  ignored for `TENANT`. `404` if nothing stored yet at that exact scope.
  Admin-checked per Section 0.
- **Retrofitted:** `PUT /api/v1/policies` now also requires the same
  `X-Session-Token` admin check (confirmed with product owner — this was
  previously fully unauthenticated). **Breaking change for any existing
  unauthenticated caller** — nothing in the built system currently calls
  this endpoint except manual `curl` during testing, so nothing automated
  breaks, but every future manual test of this endpoint needs a real admin
  session first.
- `POST /api/v1/evaluate` unchanged — still called by `iam-auth-svc`/
  `iam-enforcement-svc` on the hot path, deliberately not auth-gated the
  same way (those are service-to-service calls, not admin actions).
- Module description in this service's own contract/README should be
  corrected: it's no longer "pure logic + storage, no outbound calls" —
  it now calls `iam-session-svc` and `iam-identity-svc` for the two
  admin-gated endpoints.

---

## 2. API surface (this module's own routes — client-side, no server)

| Route | Purpose |
|---|---|
| `/login` | Resolve tenant, render login form, drive `iam-auth-svc /login` directly from the browser |
| `/` (dashboard, post-login) | Show current tenant info (`GET /tenants/{id}`), links to Clients / Policy |
| `/clients` | List (`GET /oidc-clients?tenantId=`) + create (`POST /oidc-clients`) OIDC clients |
| `/policy` | View (`GET /policies?tenantId=&scope=TENANT`) + edit (`PUT /policies`) the tenant-level policy. OU/USER-scope editing is a stretch goal within this same page, not a separate route, given the small surface. |

No route requires a "not an admin" gate beyond `/login` itself — every
actual data-changing or data-revealing call re-checks server-side
regardless of what the UI shows.

---

## 3. Audit events

No new audit events emitted by this module itself (matches
`iam-login-portal`'s precedent — it's a UI only). Newly-audited actions
live in the backends: `identity.role_changed` (1.1), and `policy.updated`
now implicitly carries a real `actorId` traceable to an authenticated
admin session rather than an anonymous caller (the `actorType`/`actorId`
on that event stay `SYSTEM`/`"iam-policy-svc"` per its existing Service 5
decision not to attribute per-call, unchanged in this pass — flagged as a
minor inconsistency worth revisiting later, not fixed now since it's a
previously-decided, already-tested behavior of `iam-policy-svc`).

---

## 4. Error handling specifics

- Every admin-gated call: `400` missing/malformed `X-Session-Token`,
  `401` invalid/expired session, `403` valid session but wrong tenant or
  non-admin role, matching the existing `ErrorResponse` shape used
  everywhere else.
- The console never assumes a `403`/`401` means "log in again" blindly —
  distinguishes "your session expired, please sign in" (401) from "you
  don't have permission" (403) in its UI copy.
- No client-side retry on any admin action (same reasoning as
  `iam-login-portal` Section 5 — a retried `PUT /policies` is user-visible
  and not blindly safe to auto-repeat).

---

## 5. Success criteria

- A user created with `role=USER` cannot reach any admin-gated endpoint
  (403), even with a fully valid session.
- A user promoted to `ADMIN` via the bootstrap `PATCH .../role` call can
  then log in through the console and successfully list/create OIDC
  clients and view/edit their own tenant's policy.
- An admin for tenant A, given tenant B's `tenantId` in a crafted request,
  is rejected (403) — the tenant-match check is enforced server-side, not
  just hidden in the UI.
- `PUT /api/v1/policies` without a session token now returns `400`/`401`
  where it previously succeeded unauthenticated — confirming the retrofit
  actually took effect, not just the new GET.
- A hard-capped tenant-level policy still cannot be overridden through the
  console's OU/USER editing (if built) — re-confirms `iam-policy-svc`'s
  existing AP-4 behavior isn't weakened by adding a UI in front of it.

---

## 6. Open questions / known gaps (flagged, not silently hidden)

- **The bootstrap `PATCH /users/{id}/role` endpoint has no auth at all.**
  Necessary to create the first admin without a chicken-and-egg problem,
  but it means anyone who can reach `iam-identity-svc` can currently
  promote any user to ADMIN. Acceptable for this MVP pass (matches the
  platform-wide D2 reality that no inter-service/caller authentication
  exists anywhere yet), but worth a real fix (e.g. a one-time setup token)
  before any real deployment.
- **Session token lives in browser `sessionStorage`**, not an httpOnly
  cookie — inherent to the already-decided "React+Vite static SPA" tech
  choice (no server to set an httpOnly cookie from). A real XSS
  vulnerability anywhere in this app would be able to read it. Flagged,
  not fixed — fixing it would mean revisiting the SPA-vs-SSR tech choice
  itself, which is out of scope for this pass to relitigate.
- **`sourceIp` for this login path is client-supplied**, unlike
  `iam-login-portal`'s server-side real-IP fix — inherent to being a pure
  SPA with no server, not a new regression.
