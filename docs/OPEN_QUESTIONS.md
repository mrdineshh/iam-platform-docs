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

- **OQ-10 -- Move the admin session token out of JavaScript's reach.** The
  console keeps the token in sessionStorage, readable by any script that runs
  in the page. The CSP above makes that much harder to exploit but does not
  remove it. The real fix is an httpOnly cookie, which needs a server-side
  piece (a backend-for-frontend, or cookie sessions in the auth service) plus
  CSRF protection and `credentials` CORS across five services. That changes the
  session transport (Tier 3) so it needs a decision. Related: SESSION_TTL is 8h
  while the login portal's cookie assumes 1h; consider a shorter lifetime for
  admin sessions.

- **OQ-11 -- Apply the OpenBao policy for SCIM tokens.** The tenant service's
  AppRole policy (`cert-issuer`) must allow `secret/data/scim/*` before a SCIM
  connection's token can be stored. `infra/openbao/bootstrap.py` now includes it,
  but it was not applied on the running server: that needs the OpenBao root
  token, which was not authorized for me to use, and re-running bootstrap.py
  rewrites `.env`. Until it is applied, saving a SCIM connection fails at the
  secret write (nothing is saved).
- **OQ-12 -- Direction of SCIM.** Built as outbound provisioning (platform pushes
  to apps), matching the request. FR-2.7 also describes SCIM as a directory
  pushing users into the platform (Entra/AD -> platform, an inbound SCIM server);
  that is not built. Third-party apps must expose a SCIM endpoint to be
  provisioned: Pulse does not (its code has no SCIM routes), so it needs one
  added, or a different mechanism, before it can be deprovisioned from here.
- **OQ-13 -- Who is provisioned to a SCIM app.** Every user of the tenant, not
  only members of groups assigned to the app. Group-scoped provisioning (create
  when a user gains access, remove when they lose it) is a possible refinement.
- **OQ-14 -- Group enforcement is now strict.** A signed-in user without a group,
  or whose group is not assigned to the app, is refused at sign-in (previously
  they could still sign in by opening the app's own link). Apps with no group
  assigned are open to admins only. At the time of this change Pulse had no group
  assigned, so only admins can sign in to Pulse until a group is assigned, and
  users with no group (employee2, employee3, ratnesh) cannot sign in to any app.
- **OQ-15 -- Suspend vs delete in apps.** Suspend sets SCIM `active=false` (kept,
  reversible); delete removes the account. Confirm this matches policy for each
  app.