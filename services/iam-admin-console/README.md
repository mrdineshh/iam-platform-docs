# iam-admin-console

Tenant admin UI (BUILD_PLAN.md Service 14, React + Vite SPA). Full spec:
`docs/specs/iam-admin-console-SPEC.md` in the `iam-platform-docs` repo.

## What this does

Lets a tenant admin manage their own tenant's OIDC clients and access
policy through a UI instead of raw `curl`. A pure static SPA — no server
of its own, unlike `iam-login-portal`.

1. Resolves the tenant from the hostname's subdomain (`FR-6.2`), same
   pattern as `iam-login-portal` — or a `?tenant=` query param in local
   dev (no wildcard DNS).
2. Logs in directly against `iam-auth-svc POST /api/v1/login` from the
   browser (password + TOTP/push, same combined-form UX as the login
   portal).
3. On success, checks the new `role` field in the login response. Only
   `role: "ADMIN"` gets past the client-side route guard — but the real
   gate is server-side: every admin-only backend call independently
   re-verifies the session and role itself (see below), so this client-side
   check is a UX convenience, not the actual security boundary.
4. Lists/creates OIDC clients (`iam-tenant-svc`) and views/edits the
   tenant-wide access policy (`iam-policy-svc`).

## New concept this module introduces: admin roles

Nothing in the platform had an admin/role concept before this. Added
alongside this console:

- `iam-identity-svc`: `User.role` (`ADMIN`|`USER`), plus a
  `PATCH /users/{id}/role` endpoint to promote the first admin (see "How
  to create the first admin" below).
- `iam-auth-svc`: `LoginResponse.role`.
- `iam-tenant-svc` / `iam-policy-svc`: each gained its own local
  `SessionClient` + `IdentityClient` and an `AdminAccessGuard` that every
  admin-only endpoint calls — validates the session, confirms it belongs to
  the tenant being acted on, and confirms the user's role is `ADMIN`.
  `PUT /api/v1/policies` (previously fully unauthenticated) now requires
  this too, not just the new endpoints.

## How to create the first admin

There's a chicken-and-egg problem: the console can't be used to promote
someone to admin before an admin exists to log into it. Bootstrap with a
direct API call:

```
curl -X PATCH http://localhost:8084/api/v1/users/<userId>/role \
  -H 'Content-Type: application/json' \
  -d '{"role":"ADMIN"}'
```

This endpoint is deliberately unauthenticated for now — see
`docs/specs/iam-admin-console-SPEC.md` Section 6 for why, and the real gap
that leaves open.

## Known, documented limitations (not hidden — see the SPEC's Section 6)

- **`sourceIp` sent to `iam-auth-svc` is a fixed, local-dev-only placeholder
  value** (`10.0.0.1`), not a real client IP — a pure browser SPA has no
  way to learn its own public IP the way `iam-login-portal`'s server-side
  `server.js` can. This value is chosen specifically to hit `iam-geo-svc`'s
  existing private-IP local-dev fixture. **This does not work, and must not
  be relied on, in a real deployment.**
- **Session token lives in `sessionStorage`**, not an httpOnly cookie —
  inherent to being a static SPA with no server.
- **User management (list/suspend/etc.) is out of scope for this pass** —
  deferred per the interview that produced the SPEC.

## Environment variables (build-time, `VITE_`-prefixed — baked into the
static bundle, never secret)

| Variable | Default | Purpose |
|---|---|---|
| `VITE_AUTH_SVC_URL` | `http://localhost:8087` | iam-auth-svc (browser-reachable, host-mapped) |
| `VITE_TENANT_SVC_URL` | `http://localhost:8082` | iam-tenant-svc |
| `VITE_POLICY_SVC_URL` | `http://localhost:8085` | iam-policy-svc |
| `VITE_ROOT_DOMAIN` | `platform.example.com` | Subdomain suffix for tenant resolution |

## Commands

```
npm install
npm run dev     # local dev server (vite)
npm test        # vitest, pure-logic unit tests
npm run build   # production build (tsc -b && vite build)
npm run preview # serve the production build locally
```
