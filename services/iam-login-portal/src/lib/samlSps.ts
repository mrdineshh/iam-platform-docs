import { config } from "./config";
import { getJson } from "./http";

export interface SamlSp {
  id: string;
  name: string;
  launchUrl: string | null;
}

/**
 * SAML counterpart to oidcClients.ts's listClients -- same tenant-svc
 * list endpoint iam-admin-console's launchpad uses (session-gated, not
 * admin-only). Needed so SAML-connected apps (e.g. Google Workspace) show
 * up on the launchpad too, not just OIDC ones.
 */
export async function listSamlSps(tenantId: string, sessionToken: string, correlationId: string): Promise<SamlSp[]> {
  const result = await getJson<SamlSp[]>(
    `${config.tenantSvcUrl}/api/v1/saml-sps?tenantId=${encodeURIComponent(tenantId)}`,
    { correlationId, timeoutMs: config.defaultTimeoutMs, headers: { "X-Session-Token": sessionToken } },
  );
  return result ?? [];
}
