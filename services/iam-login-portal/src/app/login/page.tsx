import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { randomUUID } from "node:crypto";
import { LoginForm } from "./LoginForm";
import { SplitShell } from "../SplitShell";
import { config } from "@/lib/config";
import { completeAuthorization } from "@/lib/oidcClient";
import { findTenantBySubdomain, resolveTenantSubdomain } from "@/lib/tenant";
import { brandStyle, safeLogoUrl } from "@/lib/branding";

interface SearchParams {
  client_id?: string;
  redirect_uri?: string;
  scope?: string;
  state?: string;
  // Dev-only tenant override -- see docs/specs/iam-login-portal-SPEC.md
  // Section 3. oidcprovider-svc appends this itself when its own
  // loginPortalBaseUrl doesn't contain a real "{subdomain}" host.
  tenant?: string;
}

// This entry point is only ever reached via iam-oidcprovider-svc's GET
// /authorize redirect (docs/specs/iam-login-portal-SPEC.md Section 0) --
// query params are carried through from that redirect, not typed by hand.
export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await searchParams;
  const requestHeaders = await headers();

  const clientId = params.client_id ?? "";
  const redirectUri = params.redirect_uri ?? "";
  const scope = params.scope ?? "openid";
  const state = params.state ?? "";
  const tenantOverride = params.tenant ?? null;

  if (!clientId || !redirectUri) {
    redirect("/login/error?reason=missing_params");
  }

  const correlationId = randomUUID();

  // --- Single sign-on ---
  // If this browser already holds a live platform session from an earlier
  // login (to this or any other app in the same tenant), mint the
  // authorization code straight away and never render the form. Nothing
  // here trusts the cookie on its own: /authorize/complete revalidates
  // that the session is live AND belongs to this client's tenant, so an
  // expired, terminated, or foreign session fails closed into the normal
  // login form below.
  const ssoToken = (await cookies()).get(config.ssoCookieName)?.value;
  let ssoRedirect: string | null = null;
  if (ssoToken) {
    try {
      const completion = await completeAuthorization(
        { sessionToken: ssoToken, clientId, redirectUri, scope, state },
        correlationId,
      );
      ssoRedirect = completion.redirectUri;
    } catch {
      ssoRedirect = null;
    }
  }
  // Deliberately outside the try above: redirect() signals by throwing, so
  // calling it in there would be swallowed by that catch and silently fall
  // through to the login form instead of redirecting.
  if (ssoRedirect) {
    redirect(ssoRedirect);
  }

  const subdomain = resolveTenantSubdomain(requestHeaders.get("host"), tenantOverride);
  if (!subdomain) {
    redirect("/login/error?reason=tenant_unresolved");
  }

  let tenant;
  try {
    tenant = await findTenantBySubdomain(subdomain, correlationId);
  } catch {
    redirect("/login/error?reason=unavailable");
  }

  if (!tenant) {
    redirect("/login/error?reason=tenant_not_found");
  }

  return (
    <SplitShell style={brandStyle(tenant.branding)}>
      <LoginForm
        clientId={clientId}
        redirectUri={redirectUri}
        scope={scope}
        state={state}
        tenantOverride={tenantOverride}
        tenantName={tenant.name}
        logoUrl={safeLogoUrl(tenant.branding)}
        headline={tenant.branding?.headline}
      />
    </SplitShell>
  );
}
