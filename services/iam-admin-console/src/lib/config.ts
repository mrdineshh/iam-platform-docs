// 12-factor config via environment (Vite exposes only VITE_-prefixed vars
// to browser code -- everything here is necessarily public, never a
// secret). Defaults match docker-compose.yml's host-mapped ports, since
// this is a pure browser SPA calling backend services directly, not
// through a server-side proxy the way iam-login-portal can.
export const config = {
  authSvcUrl: import.meta.env.VITE_AUTH_SVC_URL ?? "http://localhost:8087",
  tenantSvcUrl: import.meta.env.VITE_TENANT_SVC_URL ?? "http://localhost:8082",
  policySvcUrl: import.meta.env.VITE_POLICY_SVC_URL ?? "http://localhost:8085",
  oidcIssuerUrl: import.meta.env.VITE_OIDC_ISSUER_URL ?? "http://localhost:8090",
  // Used only to hand off this SPA's session into the login portal's SSO
  // cookie before launching an app -- see LaunchpadPage.tsx and
  // iam-login-portal's /sso-handoff route.
  loginPortalUrl: import.meta.env.VITE_LOGIN_PORTAL_URL ?? "http://localhost:3001",

  // See iam-login-portal's config.ts for the same pattern -- FR-6.2
  // subdomain-only tenant resolution, with a local-dev `?tenant=` fallback.
  rootDomain: import.meta.env.VITE_ROOT_DOMAIN ?? "platform.example.com",

  // MVP-TEMPORARY, LOCAL-DEV-ONLY: a pure browser SPA has no way to learn
  // its own real public IP (unlike iam-login-portal, which reads it
  // server-side off the raw TCP socket -- see that service's server.js).
  // Rather than inventing a second special-case in iam-geo-svc, this
  // deliberately reuses the EXISTING private-IP local-dev fixture
  // (contracts/iam-geo-svc.yaml / GeoLookupService.kt) by sending a fixed
  // RFC 1918 address as sourceIp. This only ever resolves via that
  // local-dev-only fixture -- it would NOT work, and must NOT be relied on,
  // against a real deployment's iam-geo-svc (which only ever sees real
  // public client IPs there). See docs/DECISIONS.md, Service 14 entry.
  devOnlySourceIp: "10.0.0.1",

  pushWaitTimeoutMs: 65_000,
  defaultTimeoutMs: 10_000,
} as const;
