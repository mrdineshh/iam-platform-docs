import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { randomUUID } from "node:crypto";
import { config } from "@/lib/config";
import { findTenantBySubdomain, resolveTenantSubdomain } from "@/lib/tenant";
import { listMyApps, type MyAppTile } from "@/lib/myApps";
import { UpstreamError } from "@/lib/http";

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
    <main className="login-page">
      <div className="apps-page">
        <h1>{tenant.name}</h1>
        <p className="hint">Your apps</p>

        {apps.length === 0 ? (
          <p>No apps are set up to launch from here yet.</p>
        ) : (
          <div className="app-tiles">
            {apps.map((app) => (
              <a key={app.id} href={app.launchUrl} target="_blank" rel="noopener noreferrer" className="app-tile">
                <span className="app-tile__icon" aria-hidden="true">
                  {app.name.charAt(0).toUpperCase()}
                </span>
                <span className="app-tile__name">{app.name}</span>
              </a>
            ))}
          </div>
        )}
      </div>
    </main>
  );
}

function portalUrl(tenantOverride: string | null): string {
  return tenantOverride ? `/portal?tenant=${encodeURIComponent(tenantOverride)}` : "/portal";
}
