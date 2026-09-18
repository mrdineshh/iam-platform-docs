# iam-login-portal — SPEC

BUILD_PLAN.md Service 13. Next.js (SSR), branded login UI. Replaces
iam-oidcprovider-svc's built-in placeholder login form (BUILD_PLAN.md Service
11 entry, docs/DECISIONS.md: "Login form is a deliberate stand-in ... replaced,
not mistaken for the real thing, when Service 13 is built").

Scope for this SPEC: **the OIDC-driven login flow only** — password entry,
second-factor (TOTP or push), and the standard denial/error states. Self-service
password reset and MFA/device management (BRD FR-2.14) are explicitly deferred
to a future SPEC; no backend endpoints for them exist yet either.

This module is a UI/orchestration layer with no database of its own. Its "data
schema" section below is empty by design; instead it documents the backend
contract changes it depends on, since those changes touch two previously-built
services (iam-oidcprovider-svc, iam-tenant-svc) and must be called out
explicitly per BUILD_PLAN.md's "never modify a previously built contract
without confirmation" rule. (Confirmed with product owner during the interview
for this SPEC — same "extend a previously-built service, same session" pattern
already used for iam-tenant-svc during Service 11.)

---

## 0. Architecture — the handoff (confirmed with product owner)

```
Grafana → iam-oidcprovider-svc: GET /authorize?client_id=...&redirect_uri=...
  → oidcprovider-svc validates client_id/redirect_uri (unchanged: 400 direct,
    never a redirect, on invalid client/redirect_uri)
  → oidcprovider-svc looks up the client's tenant (GET /api/v1/tenants/{id},
    already exists) for its subdomain
  → 302 redirect to iam-login-portal, subdomain-scoped:
      https://{subdomain}.{LOGIN_PORTAL_DOMAIN}/login?client_id=...&redirect_uri=...&scope=...&state=...
    (local dev fallback: LOGIN_PORTAL_DOMAIN has no wildcard DNS, so the
    redirect instead targets a single dev host with an explicit
    `&tenant={subdomain}` query param appended — see Section 5)

Browser → iam-login-portal (the actual front door now — this is where the
  real client IP must be read from the raw HTTP connection, the same fix
  Service 11 made for POST /authorize/login, now living here instead since
  that's no longer where the literal browser submission lands):
  - resolves tenant from Host header subdomain (prod) or ?tenant= (local dev)
  - renders password form
  - on submit: calls iam-auth-svc POST /api/v1/login server-side (tenantId,
    email, password, sourceIp=real client IP, totpCode if the user chose the
    TOTP path)
  - on 403 needing a second factor... (see Section 2 — no separate endpoint;
    auth-svc's contract already folds this into the same /login call, so the
    portal drives it as two possible submissions of the same form, not two
    endpoints — see Section 2 for the exact UX)
  - once iam-auth-svc returns 200 with a session token, iam-login-portal
    calls the NEW iam-oidcprovider-svc endpoint:
      POST /authorize/complete { sessionToken, client_id, redirect_uri, scope, state }
    server-side (this is a service-to-service call — the session token is
    never sent to or stored in the browser)
  - oidcprovider-svc re-validates client_id/redirect_uri (defense in depth,
    doesn't trust the earlier /authorize validation happened for this exact
    request), validates the session via iam-session-svc, mints a single-use
    authorization code (unchanged mechanism/TTL from the current
    implementation), and returns { code, redirectUri } as JSON
  - iam-login-portal issues the actual 302 to the browser:
      redirectUri + "?code=" + code + "&state=" + state
  → Grafana receives the code, exchanges it at /token (unchanged)
```

Why this shape: matches BUILD_PLAN.md's own diagram ("iam-oidcprovider-svc
redirects to iam-login-portal → login portal → iam-auth-svc") exactly, and is
the first time iam-auth-svc's TOTP/push second factor becomes reachable from a
real login — the current placeholder form never accepted a `totpCode` at all.

---

## 1. Backend contract changes required (implemented alongside this module)

### 1.1 `iam-oidcprovider-svc` (contracts/iam-oidcprovider-svc.yaml)

- `GET /authorize`: behavior change, same request/response shape for the
  error cases (400 on invalid client_id/redirect_uri, unchanged). Success
  case changes from "renders HTML form" to "302 redirect to iam-login-portal"
  as described in Section 0.
- `POST /authorize/login`: **removed**. Nothing external ever called it
  (it backed only the now-removed inline HTML form), so this is a clean
  removal, not a versioned deprecation.
- `POST /authorize/complete`: **new**.
  - Request (JSON): `{ sessionToken, client_id, redirect_uri, scope, state }`
    — all required.
  - `200`: `{ redirectUri: string }` — the full URL (client's redirect_uri +
    `?code=...&state=...`) for the caller (iam-login-portal) to redirect the
    browser to. Returned as JSON, not a raw 302, because this is a
    service-to-service call, not a browser request.
  - `400`: invalid/unregistered client_id or redirect_uri (same
    ErrorResponse shape as the rest of the contract).
  - `401`: sessionToken unknown/expired (mirrors iam-session-svc's own 404
    on validate, translated to 401 here since from this endpoint's caller's
    perspective it's an authentication failure, not a missing resource).
  - `503`: iam-session-svc or iam-tenant-svc unavailable.
  - Authorization code minting, TTL, and single-use/GETDEL semantics are
    unchanged from the current implementation — only how the code gets
    triggered changes (a validated session token instead of a raw
    password form post).
- The real-client-IP extraction logic documented in the Service 11
  DECISIONS.md entry moves to iam-login-portal (Section 0) since
  oidcprovider-svc no longer receives the literal browser form submission.
  No functional change to oidcprovider-svc itself here beyond removing the
  now-dead code path.

### 1.2 `iam-tenant-svc` (contracts/iam-tenant-svc.yaml)

- `GET /api/v1/tenants/by-subdomain/{subdomain}`: **new** (Tier-2, logged in
  DECISIONS.md — additive read endpoint on data this service already owns,
  same pattern as Service 11's tenant-svc extension).
  - `200`: `Tenant` (same schema as `GET /api/v1/tenants/{id}`).
  - `404`: no tenant with this subdomain.
  - Used by iam-login-portal to resolve `tenantId` from the Host header
    subdomain (production path) — see Section 5.

### 1.3 `iam-auth-svc` (contracts/iam-auth-svc.yaml)

- `ErrorResponse`: add a required-on-403 `errorCode` field (Tier-2, logged in
  DECISIONS.md — additive, doesn't break existing callers since `reason`
  stays as free text for humans). Enum, refined against the real
  `AuthService.login` denial sites during implementation (see
  docs/DECISIONS.md, Service 13 implementation entry — no
  `SECOND_FACTOR_REQUIRED` value: there's no separate password-only check
  to require a second factor *from*, since `/login` always evaluates both
  in one call):
  `ACCOUNT_SUSPENDED | LOCATION_UNVERIFIED | POLICY_UNAVAILABLE |
  POLICY_DENIED | NO_SECOND_FACTOR_ENROLLED | NO_PUSH_DEVICE_ENROLLED |
  SECOND_FACTOR_UNAVAILABLE | TOTP_INVALID | TOTP_LOCKED | PUSH_DENIED |
  PUSH_TIMEOUT`. This is how iam-login-portal distinguishes each denial
  cause for the right UI message without parsing free text (resolved as
  OQ-3, confirmed with product owner — see Section 6).
- `LoginRequest`: unchanged.

No changes needed to iam-session-svc or iam-device-svc contracts —
iam-login-portal calls both exactly as already published (the latter only
indirectly, through iam-auth-svc's existing orchestration).

---

## 2. Second-factor UX (confirmed with product owner)

iam-auth-svc's `/login` has no separate "which factor" endpoint: omitting
`totpCode` makes the call itself block up to 60s waiting on a push response.
The portal exposes both paths explicitly rather than guessing:

1. After a successful password submission returns a `403` indicating a
   second factor is required (auth-svc's contract doesn't currently
   distinguish "need 2FA" from other 403 causes in a machine-readable way —
   **flagged in Section 6, Open Question OQ-1**), the portal shows a second
   screen with:
   - a 6-digit TOTP code input (submit → calls `/login` again with the same
     tenantId/email/password plus `totpCode` — fast, synchronous), and
   - a "Send a push to my phone" button (submit → calls `/login` again with
     `totpCode` omitted — the portal shows an explicit "Check your phone —
     waiting up to 60 seconds" state with a spinner and a Cancel button
     while that request is in flight).
2. Password is resubmitted alongside the second factor on both paths (no
   separate short-lived "pending login" state is held anywhere — this
   matches auth-svc's actual contract, which only exposes one endpoint that
   takes the full credential set every time).
3. Cancelling the push wait is a client-side UI abandon only — the portal
   cannot cancel the in-flight server call (no cancellation endpoint exists
   on iam-device-svc), so the request completes on the backend regardless;
   the portal just stops showing the spinner and lets the user retry.

---

## 3. Tenant resolution (confirmed with product owner)

- **Production path:** parse the subdomain from the `Host` header on every
  request; call `GET /api/v1/tenants/by-subdomain/{subdomain}` (Section 1.2)
  to resolve `tenantId`. Unknown subdomain → a generic "tenant not found"
  error page (never leaks whether *some* tenant exists vs. a typo).
- **Local Docker Compose dev override:** no wildcard DNS locally, so a
  `?tenant=<subdomain>` query param is accepted as a fallback when the Host
  header doesn't contain a recognizable subdomain (i.e., it's the raw
  `localhost:3001` dev host). Same pattern already used for iam-geo-svc's
  private-IP fixture: explicitly labeled as dev-only, never fires against a
  real subdomain-routed request, documented in the module README.
- oidcprovider-svc's `GET /authorize` redirect (Section 0) is responsible for
  producing a URL the browser can actually reach in both cases — in local
  dev it appends `&tenant={subdomain}` to the redirect target instead of
  constructing a subdomain hostname it knows won't resolve.

---

## 4. API surface (this module's own routes)

All routes are Next.js Route Handlers / Server Actions — server-side only,
nothing here calls a backend service directly from client-side JS.

| Route | Method | Purpose |
|---|---|---|
| `/login` | GET | Renders the password form. Reads `client_id`, `redirect_uri`, `scope`, `state` from the query string (passed through from oidcprovider-svc's redirect) and carries them as hidden fields. |
| `/login` (server action) | POST | Submits password (+ optional `totpCode`, or a `usePush=true` flag). Calls `iam-auth-svc POST /api/v1/login` server-side with the real client IP. On second-factor-required, re-renders with the Section 2 UI. On success, calls `iam-oidcprovider-svc POST /authorize/complete` and 302-redirects the browser to the returned `redirectUri`. |
| `/login/error` | GET | Generic error page for tenant-not-found / invalid OIDC params carried over from a bad redirect (defense in depth — oidcprovider-svc already validates these before redirecting here, but a malformed/hand-crafted URL must not crash the portal). |

No `/api/v1/...` surface of its own — this module has nothing else to expose;
it is purely a UI in front of already-published backend contracts.

---

## 5. Error handling specifics (deltas from Guardrails Section 2)

- **No client-side automatic retry on login submission.** A failed/timed-out
  call to iam-auth-svc's `/login` is not automatically retried by the
  browser or the portal — unlike Resilience4j's backend-to-backend retries,
  a retried login is user-visible and (per the Service 11 DECISIONS.md
  entry) only safe because of the correlation-ID → Idempotency-Key chain;
  the portal preserves that by reusing the same `X-Correlation-Id` if the
  user manually resubmits the identical form state, but does not retry
  silently.
- **Timeouts:** the push-approval submission needs a client HTTP timeout
  strictly longer than iam-auth-svc's own 60s blocking wait (set to 65s) —
  otherwise the portal would time out and show a spurious error while the
  backend push challenge is still legitimately pending.
- **Downstream 503s** (any of iam-auth-svc, iam-oidcprovider-svc,
  iam-tenant-svc unavailable) render a generic "service temporarily
  unavailable, try again" page — never a stack trace or raw error body.
- **Never fail open:** if tenant resolution, client_id/redirect_uri
  validation, or the `/authorize/complete` call fails for any reason, the
  portal shows an error — it never falls back to treating an unresolvable
  state as a successful login (matches BUILD_PLAN.md Section 4.6's rule,
  already binding on every other module).
- No audit events are emitted directly by this module — it has no Kafka
  producer (out of scope per the tech stack table: Next.js is UI-only). All
  security-relevant events on this path (`auth.login_succeeded`,
  `auth.login_denied`, the new `/authorize/complete` code issuance) are
  emitted by iam-auth-svc / iam-oidcprovider-svc exactly as they already are
  today — this module doesn't change what gets audited, only how the
  browser gets to those calls.

---

## 6. Open questions / Tier-3 flags — RESOLVED

- **OQ-3 (resolved, confirmed with product owner):** Add a required-on-403
  `errorCode` enum field to iam-auth-svc's `ErrorResponse` (see Section 1.3
  for the final list, refined during implementation) rather than having the
  portal parse free text. Logged in DECISIONS.md as a Tier-2 additive contract
  change once implemented.

- **OQ-4 (resolved, confirmed with product owner):** Per-tenant branding
  (BRD FR-6.1) is deferred. iam-login-portal ships one static, generic
  platform theme for every tenant in this SPEC; FR-6.1 remains open/
  unsatisfied and gets its own SPEC later once a storage location (likely an
  iam-tenant-svc extension) and an admin UI exist to configure it. Not
  silently marked done.
- **Note (Tier-1, not an open question):** Local Docker Compose host port for
  iam-login-portal is `3001` (container listens on `3000` internally; `3000`
  was already bound by an unrelated local process on the dev machine this
  was verified on), added to docker-compose.yml alongside the existing
  8081–8090 backend range.

---

## 7. Success criteria (module-specific, beyond generic DoD)

- `GET /authorize` with a valid client_id/redirect_uri redirects to
  iam-login-portal (not an inline HTML response) — confirmed via `curl -v`,
  no HTML body, a `Location` header pointing at the portal.
- A full password + TOTP login round-trip through the portal reaches
  `/token` and returns valid RS256 JWTs — the exact same outcome as the old
  Service 11 TEST GATE, but driven through the new portal instead of the
  placeholder form.
- A full password + push login round-trip works, with the portal visibly
  blocking on the "check your phone" state for the duration of a real
  `iam-mobile-android`-less manual `POST /api/v1/devices/push/respond` call
  used to simulate the phone tap (same approach Service 9's own TEST GATE
  used).
- Wrong password, locked TOTP, denied push, push timeout, and blocked-country
  policy denial each render a distinct, correct error state (not a generic
  failure) — driven off the new `errorCode` field (Section 1.3), not by
  parsing `reason` text.
- Killing the underlying session via iam-session-svc mid-flow (simulating
  iam-enforcement-svc) still correctly invalidates the OIDC access token via
  `/userinfo`, exactly as already proven in Service 11 — this module doesn't
  change that guarantee, and the TEST GATE re-confirms it isn't broken by
  the handoff change.
- Unknown subdomain and unknown `?tenant=` override both produce the generic
  "tenant not found" page, never a 500 or a stack trace.
