/**
 * The address a newly created user opens to sign in. Until each organization has its own wildcard DNS name
 * (FR-6.2), the login portal finds the organization from the `?tenant=` part.
 */
export function userSignInLink(loginPortalUrl: string, subdomain: string | null): string {
  const base = `${loginPortalUrl.replace(/\/+$/, "")}/login`;
  return subdomain ? `${base}?tenant=${encodeURIComponent(subdomain)}` : base;
}
