# iam-login-portal

Branded login UI (BUILD_PLAN.md Service 13, Next.js/SSR). Full spec:
`docs/specs/iam-login-portal-SPEC.md` in the `iam-platform-docs` repo.

## What this does

Replaces `iam-oidcprovider-svc`'s built-in placeholder login form. When a
third-party app (e.g. Grafana) starts an OIDC login, `iam-oidcprovider-svc`'s
`GET /authorize` redirects here instead of rendering its own HTML. This
service:

1. Resolves the tenant from the request's subdomain (`FR-6.2`) -- or, in
   local Docker Compose (no wildcard DNS), a `?tenant=` query param
   `iam-oidcprovider-svc` appends itself.
2. Renders a password + second-factor form.
3. Calls `iam-auth-svc`'s single `/login` endpoint directly (AP-1 -- no
   separate MFA endpoint exists), with either a TOTP code or no code at all
   (which makes that call block server-side for up to 60s on a push
   approval).
4. On success, calls the new `iam-oidcprovider-svc POST /authorize/complete`
   with the resulting session token (server-to-server; the token never
   reaches the browser) to mint a single-use authorization code.
5. Redirects the browser to the third-party app's `redirect_uri` with that
   code.

This is also the actual front door for the real client IP now: `server.js`
wraps Next's request handler to read `req.socket.remoteAddress` off the raw
TCP connection and inject it under an internal header
(`x-iam-internal-real-ip`) that a client can't spoof (it's overwritten, not
appended, for every request) before Next ever sees it. `iam-auth-svc`'s
`sourceIp` is populated from that header, not a client-supplied field.

## Explicitly out of scope (see SPEC Section 6, resolved with product owner)

- Per-tenant branding (logo/color/theme, `FR-6.1`) -- one static generic
  theme for every tenant. No backend owns branding data yet.
- Self-service password reset / MFA enrollment (`FR-2.14`) -- a future
  module; no backend endpoints for it exist yet either.

## Backend contract changes this module depends on

- `iam-oidcprovider-svc`: `GET /authorize` now redirects here instead of
  rendering HTML; `POST /authorize/login` removed; `POST /authorize/complete`
  added.
- `iam-tenant-svc`: `GET /api/v1/tenants/by-subdomain/{subdomain}` added.
- `iam-auth-svc`: `ErrorResponse.errorCode` added (populated on every 403
  from `/login`).

All three are already implemented (see `docs/DECISIONS.md`, Service 13
pre-implementation entry, in `iam-platform-docs`).

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `AUTH_SVC_URL` | `http://iam-auth-svc:8080` | iam-auth-svc |
| `TENANT_SVC_URL` | `http://iam-tenant-svc:8080` | iam-tenant-svc |
| `OIDCPROVIDER_SVC_URL` | `http://iam-oidcprovider-svc:8080` | iam-oidcprovider-svc |
| `LOGIN_PORTAL_ROOT_DOMAIN` | `platform.example.com` | Subdomain suffix for tenant resolution (`FR-6.2`) |
| `PORT` | `3000` | HTTP port `server.js` listens on |

## Commands

```
npm install
npm run dev     # local dev server (next dev)
npm test        # vitest, pure-logic unit tests (tenant resolution, error-code mapping)
npm run build   # production build
npm start       # node server.js, against the production build
```

## No database, no Kafka producer

This module has no data of its own and no audit events of its own to emit
-- every security-relevant event on this path (`auth.login_success`,
`auth.login_denied`, OIDC code/token issuance) is emitted by `iam-auth-svc`
/ `iam-oidcprovider-svc` exactly as before; this module only changes how the
browser gets to those calls.
