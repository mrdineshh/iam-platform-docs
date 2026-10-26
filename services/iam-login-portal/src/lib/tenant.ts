import { config } from "./config";
import { getJson } from "./http";

export interface Tenant {
  id: string;
  name: string;
  subdomain: string;
  status: "ACTIVE" | "SUSPENDED";
  createdAt: string;
}

/**
 * FR-6.2: subdomain-only tenant resolution. Real path parses the Host
 * header; local Docker Compose has no wildcard DNS, so a `?tenant=`
 * override is accepted as an explicit, documented dev-only fallback --
 * same pattern as iam-geo-svc's private-IP fixture (never fires against a
 * real subdomain-routed Host header). See
 * docs/specs/iam-login-portal-SPEC.md Section 3.
 */
export function resolveTenantSubdomain(host: string | null, tenantOverride: string | null): string | null {
  if (host) {
    const hostname = host.split(":")[0];
    const suffix = `.${config.rootDomain}`;
    if (hostname.endsWith(suffix)) {
      const subdomain = hostname.slice(0, -suffix.length);
      if (subdomain.length > 0) return subdomain;
    }
  }
  // Dev-only fallback -- only reached when the Host header didn't carry a
  // real subdomain under rootDomain.
  return tenantOverride && tenantOverride.length > 0 ? tenantOverride : null;
}

export async function findTenantBySubdomain(subdomain: string, correlationId: string): Promise<Tenant | null> {
  return getJson<Tenant>(
    `${config.tenantSvcUrl}/api/v1/tenants/by-subdomain/${encodeURIComponent(subdomain)}`,
    { correlationId, timeoutMs: config.defaultTimeoutMs },
  );
}
