import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { randomUUID } from "node:crypto";
import { config } from "@/lib/config";
import { findTenantBySubdomain, resolveTenantSubdomain } from "@/lib/tenant";
import { brandStyle, safeLogoUrl } from "@/lib/branding";
import { listMyApps, type MyAppTile } from "@/lib/myApps";
import { UpstreamError } from "@/lib/http";
import { getMe } from "@/lib/me";
import { Launchpad } from "./Launchpad";

interface SearchParams {
  tenant?: string;
}

/**
 * "Click the app icon, you're in" -- the launchpad for a user who signed in
 * directly at /portal rather than arriving via an app's own SSO button.
 * Lists every app this user is allowed to launch, from iam-tenant-svc's
 * group-filtered /my-apps endpoint (an ADMIN sees every connected app with
 * a launchUrl, a regular user only sees apps assigned to their own group --
 * see MyAppsController's doc comment). Each tile's launchUrl points at that
 * app's own login-start endpoint, which redirects back into /authorize or
 * /saml/sso here; because the SSO cookie this same login already set is
 * still present, that round-trip completes silently (see /login/page.tsx's
 * completeAuthorization shortcut) -- no second login, matching the
 * one-login-many-apps requirement.
 */
export default async function AppsPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await searchParams;
  const requestHeaders = await headers();
  const tenantOverride = params.tenant ?? null;
  const correlationId = randomUUID();

  const ssoToken = (await cookies()).get(config.ssoCookieName)?.value;
  if (!ssoToken) {
    redirect(portalUrl(tenantOverride));
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

  const me = await getMe(ssoToken, correlationId);

  let apps: MyAppTile[];
  try {
    apps = await listMyApps(tenant.id, ssoToken, correlationId);
  } catch (err) {
    // An expired/terminated session shows up here as a 401 from tenant-svc's
    // session check -- never fail open into an empty-but-silent page, send
    // the user back to sign in again.
    if (err instanceof UpstreamError && err.status === 401) {
      redirect(portalUrl(tenantOverride));
    }
    apps = [];
  }

  return (
    <div style={brandStyle(tenant.branding)}>
      <Launchpad
        tenantName={tenant.name}
        logoUrl={safeLogoUrl(tenant.branding)}
        apps={apps}
        user={me ? { name: me.displayName, email: me.email } : null}
        tenantOverride={tenantOverride}
      />
    </div>
  );
}

function portalUrl(tenantOverride: string | null): string {
  return tenantOverride ? `/portal?tenant=${encodeURIComponent(tenantOverride)}` : "/portal";
}
