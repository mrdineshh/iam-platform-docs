# iam-oidcprovider-svc

Service 11 in `BUILD_PLAN.md`'s build order -- the downstream OIDC provider.
Lets a third-party app (e.g. Grafana) use this platform as its login,
without duplicating any login logic: every real decision (password,
second factor, location/policy, session) is made by `iam-auth-svc`
(Service 7) and the services behind it. This service is a thin, standards-
shaped wrapper around that.

## Contract

`iam-platform-docs/contracts/iam-oidcprovider-svc.yaml` --
`/authorize`, `/authorize/login`, `/token`, `/userinfo`,
`/.well-known/openid-configuration`, `/jwks.json`. These five paths are
NOT under `/api/v1` -- they're standardized OIDC/OAuth2 locations generic
client libraries expect exactly there.

## Setting up a third-party app to connect

```
POST /api/v1/oidc-clients   (on iam-tenant-svc, port 8082)
  { "tenantId": "...", "name": "Grafana", "redirectUris": ["https://your-app/callback"] }
  -> { "clientId": "...", "clientSecret": "..." }   (secret shown once, never again)
```

Give the third-party app:
- **Issuer:** `http://localhost:8090` (or whatever `OIDC_ISSUER` is set to)
- **Client ID / Secret:** from the response above
- **Scopes:** `openid profile email`

The app's own OIDC library handles the rest via
`/.well-known/openid-configuration`.

## The login form is a stand-in, not the real thing

`iam-login-portal` (Service 13) doesn't exist yet, so `GET /authorize`
renders a minimal built-in HTML form. Replace this entirely once Service
13 exists -- `/authorize` should redirect to it instead of rendering HTML
directly.

## Two decisions worth knowing about

- **This is where the real-client-IP fix actually lives.** Every other
  service in this project either has no real front door yet, or accepts a
  client-supplied `sourceIp` as a documented MVP shortcut. `POST
  /authorize/login` is different: it's the literal browser form submission,
  so it reads `request.remoteAddr` for real and passes that down to
  `iam-auth-svc`.
- **Access tokens never contain the raw platform session token.** If they
  did, a third-party app holding an access token could impersonate the
  user's session against every other service, not just call `/userinfo`.
  Instead, a server-side Valkey mapping links the access token to the
  session, so `/userinfo` can re-check liveness without ever exposing it.
  This is also what makes `iam-enforcement-svc` killing a session
  immediately invalidate the OIDC token too, not just at its own expiry.

## Local-testing note

Docker Compose requests arrive at this service from Docker's internal
gateway IP (e.g. `172.19.0.1`), which no real GeoIP database resolves.
`iam-geo-svc` has a narrow, explicitly-labeled fixture for this (any RFC
1918 private address resolves to a fixed test country) -- see its own
README/`docs/DECISIONS.md`. This can never fire against a real deployment.

## Callers / callees

- **Calls:** `iam-tenant-svc` (client lookup/secret verification),
  `iam-auth-svc` (drives the actual login), `iam-session-svc` (confirms
  session liveness for `/userinfo`).
- **Produces:** `oidc.token_issued` to `audit-events`.

## Build / run

```
./gradlew build
./gradlew bootRun
```

## TEST GATE (BUILD_PLAN.md §6, adapted -- no Grafana in this environment)

Register a client. `/authorize` with an unknown client or unregistered
redirect_uri never redirects, only a direct `400`. A real login (real
password + a real, independently-computed TOTP code) redirects with a
single-use code. Exchanging it returns real signed JWTs. `/userinfo` works
while the session is live and returns `401` the instant the session is
deleted. Reused codes and wrong client secrets are both rejected. Full
chain visible as one linked trace in Jaeger across all ten services.
