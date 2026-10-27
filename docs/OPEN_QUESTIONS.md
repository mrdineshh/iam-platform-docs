# Open Questions / Tier-3 Flags Awaiting Human Input

Per ENGINEERING_GUARDRAILS.md §4 (Definition of Done), this file must be
empty before a module is marked done. All Tier-3 items surfaced during the
Module 1 interview were resolved with the product owner and are recorded in
`/docs/DECISIONS.md` (2026-08-03 entries) rather than left pending here.

(No open items at this time. OQ-1 and OQ-2, raised 2026-09-13 during
Service 6, are both resolved -- see `docs/DECISIONS.md`, "Tracing fix and
session-token header move" entry.)


## Open items raised 2026-10-27 (session management, branding, password and lockout policy)

Built because the product owner asked for them; recorded here because each
rests on an assumption a human should confirm.

- **OQ-3 -- Lockout disclosure.** A locked account answers a *wrong* password
  exactly like an unknown user (no lock information leaks), and reports
  `ACCOUNT_LOCKED` only when the *correct* password is supplied. This stops
  lockout state from enabling user enumeration, at the cost that a legitimate
  user who mistypes while locked sees "invalid credentials". Confirm this is
  the wanted trade-off (touches the auth engine, AP-1).
- **OQ-4 -- Lockout default.** FR-3.5 makes lockout configurable but states no
  default. It ships OFF so no existing tenant (including this demo's admin) can
  be locked out by a rollout. Confirm whether new tenants should default to
  on (for example 5 attempts, 15 minutes).
- **OQ-5 -- Sign-in alerts.** Requested ("alert on new sign-in") but no
  BRD requirement covers user notifications, and it needs mail or SMS
  infrastructure. Not built.
- **OQ-6 -- Remaining password policy.** FR-3.2 (history), FR-3.3
  (rotation/expiry) and FR-3.4 (breached-password screening, an external
  HIBP-style dependency not in the approved tech stack) are not built. Only
  FR-3.1 (complexity) and FR-3.5 (lockout) are.
- **OQ-7 -- Logo upload.** Branding takes an https logo URL only. Uploading
  needs object storage (a new dependency) and image validation. Also note the
  login page then loads the logo from the tenant's chosen host; consider a
  Content-Security-Policy `img-src` allowance if CSP is added later.
- **OQ-8 -- Session list/revoke has no explicit FR.** Mapped to FR-11.1 and
  AP-2. Confirm it is in scope for v1 (it is a standard enterprise control).
- **OQ-9 -- `/api/v1/security-settings` is unauthenticated.** Same exposure as
  `/api/v1/evaluate` on the plain-HTTP iam-policy-svc (callers are backends
  holding no admin session). It reveals password rules and the lockout
  threshold. Consider restricting the route at the network edge.
