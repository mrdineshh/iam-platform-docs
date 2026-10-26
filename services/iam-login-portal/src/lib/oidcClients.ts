import { config } from "./config";
import { getJson } from "./http";

export interface OidcClient {
  clientId: string;
  name: string;
  launchUrl: string | null;
}

/**
 * Backs the "My Apps" launchpad (/apps) -- same tenant-svc endpoint
 * iam-admin-console's launchpad uses (session-gated, not admin-only: see
 * OidcClientController.listClients). Called with the SSO cookie's session
 * token, so the list a user sees here is exactly what they're entitled to
 * launch with the session they already have -- no separate app-level login.
 */
export async function listClients(tenantId: string, sessionToken: string, correlationId: string): Promise<OidcClient[]> {
  const result = await getJson<OidcClient[]>(
    `${config.tenantSvcUrl}/api/v1/oidc-clients?tenantId=${encodeURIComponent(tenantId)}`,
    { correlationId, timeoutMs: config.defaultTimeoutMs, headers: { "X-Session-Token": sessionToken } },
  );
  return result ?? [];
}
