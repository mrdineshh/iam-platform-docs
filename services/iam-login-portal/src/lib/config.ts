// 12-factor config via environment (BUILD_PLAN.md Section 1) -- no
// hardcoded service URLs. Defaults match docker-compose.yml's internal
// service names/ports.
export const config = {
  authSvcUrl: process.env.AUTH_SVC_URL ?? "http://iam-auth-svc:8080",
  tenantSvcUrl: process.env.TENANT_SVC_URL ?? "http://iam-tenant-svc:8080",
  oidcProviderSvcUrl: process.env.OIDCPROVIDER_SVC_URL ?? "http://iam-oidcprovider-svc:8080",

  // The platform's own subdomain suffix (FR-6.2), e.g. a request to
  // "acme.platform.example.com" resolves tenant subdomain "acme". Local
  // Docker Compose has no wildcard DNS for this at all, so the Host header
  // will just be "localhost:3001" (or similar) and this never matches --
  // see resolveTenantSubdomain in tenant.ts for the dev-only `?tenant=`
  // fallback that covers that case, matching iam-geo-svc's private-IP
  // fixture pattern (docs/specs/iam-login-portal-SPEC.md Section 3).
  rootDomain: process.env.LOGIN_PORTAL_ROOT_DOMAIN ?? "platform.example.com",

  // The push-approval second-factor path blocks synchronously in
  // iam-auth-svc for up to 60s (contracts/iam-device-svc.yaml). This must
  // stay strictly longer, or the portal times out on a request that's
  // still legitimately pending (docs/specs/iam-login-portal-SPEC.md
  // Section 5).
  pushWaitTimeoutMs: 65_000,
  defaultTimeoutMs: 10_000,

  // --- Single sign-on session cookie ---
  // Holds the platform session token iam-auth-svc issued, so a *second*
  // app's /authorize redirect can reuse the existing session instead of
  // prompting for password + second factor again. This is the standard
  // IdP session-cookie pattern (what accounts.google.com does). httpOnly,
  // so browser JS can never read the token.
  ssoCookieName: "iam_sso_session",
  // Matches iam-session-svc's own 1h TTL -- the cookie must never outlive
  // the session it points at. A stale one is harmless regardless, since
  // /authorize/complete revalidates the session on every single use.
  ssoCookieMaxAgeSeconds: 60 * 60,
  // TLS terminates at the reverse proxy in front of this service, so the
  // browser is always on HTTPS even though this process sees plain HTTP.
  // Same escape hatch as iam-enforcement-svc's GATEWAY_COOKIE_SECURE for
  // a genuinely plain-http local run.
  ssoCookieSecure: (process.env.SSO_COOKIE_SECURE ?? "true") !== "false",
} as const;
