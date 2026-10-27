import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { randomUUID } from "node:crypto";
import { LoginForm } from "../login/LoginForm";
import { config } from "@/lib/config";
import { findTenantBySubdomain, resolveTenantSubdomain } from "@/lib/tenant";
import { brandStyle, safeLogoUrl } from "@/lib/branding";

interface SearchParams {
  // Dev-only tenant override -- see resolveTenantSubdomain.
  tenant?: string;
}

/**
 * The direct, "no specific app yet" entry point -- what a user visits by
 * going straight to the platform instead of clicking "Sign in with SSO"
 * from an app like Pulse. Same LoginForm wizard as /login (group-based
 * policy/2FA, identical backend contract), but with no clientId/redirectUri
 * to complete an OIDC authorization for -- on success it just lands on
 * /apps, the launchpad, instead of bouncing back to a third-party app.
 */
export default async function PortalLoginPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await searchParams;
  const requestHeaders = await headers();
  const tenantOverride = params.tenant ?? null;

  // Already holding a live session -- skip the form entirely.
  const ssoToken = (await cookies()).get(config.ssoCookieName)?.value;
  if (ssoToken) {
    redirect(appsUrl(tenantOverride));
  }

  const subdomain = resolveTenantSubdomain(requestHeaders.get("host"), tenantOverride);
  if (!subdomain) {
    redirect("/login/error?reason=tenant_unresolved");
  }

  const correlationId = randomUUID();
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
    <main className="login-page" style={brandStyle(tenant.branding)}>
      <LoginForm
        clientId=""
        redirectUri=""
        scope="openid"
        state=""
        tenantOverride={tenantOverride}
        tenantName={tenant.name}
        logoUrl={safeLogoUrl(tenant.branding)}
        headline={tenant.branding?.headline}
      />
    </main>
  );
}

function appsUrl(tenantOverride: string | null): string {
  return tenantOverride ? `/apps?tenant=${encodeURIComponent(tenantOverride)}` : "/apps";
}
