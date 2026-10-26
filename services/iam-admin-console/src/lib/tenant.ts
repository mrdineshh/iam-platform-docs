import { config } from "./config";
import { http } from "./http";

export interface Tenant {
  id: string;
  name: string;
  subdomain: string;
  status: "ACTIVE" | "SUSPENDED";
  createdAt: string;
}

/**
 * FR-6.2 subdomain resolution -- identical logic to
 * iam-login-portal's src/lib/tenant.ts resolveTenantSubdomain, reimplemented
 * here (browser-side, no shared code across the two frontend repos, same
 * "duplication is the cost of independence" reasoning used across every
 * backend client pair in this platform).
 */
export function resolveTenantSubdomain(hostname: string, tenantOverride: string | null): string | null {
  const suffix = `.${config.rootDomain}`;
  if (hostname.endsWith(suffix)) {
    const subdomain = hostname.slice(0, -suffix.length);
    if (subdomain.length > 0) return subdomain;
  }
  return tenantOverride && tenantOverride.length > 0 ? tenantOverride : null;
}

export async function findTenantBySubdomain(subdomain: string): Promise<Tenant | null> {
  try {
    return await http.get<Tenant>(`${config.tenantSvcUrl}/api/v1/tenants/by-subdomain/${encodeURIComponent(subdomain)}`);
  } catch {
    return null;
  }
}

export async function getTenant(tenantId: string): Promise<Tenant> {
  return http.get<Tenant>(`${config.tenantSvcUrl}/api/v1/tenants/${tenantId}`);
}

/**
 * Onboards a brand-new tenant. No X-Session-Token -- there's no session to
 * hold yet at this point (this is how the very first tenant/user comes to
 * exist at all), matching iam-tenant-svc's POST /api/v1/tenants, which is
 * deliberately unauthenticated server-side (see contracts/iam-tenant-svc.yaml).
 */
export async function createTenant(name: string, subdomain: string): Promise<Tenant> {
  return http.post<Tenant>(`${config.tenantSvcUrl}/api/v1/tenants`, { name, subdomain });
}
