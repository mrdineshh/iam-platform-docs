import { config } from "./config";
import { getJson } from "./http";

export interface MyAppTile {
  id: string;
  name: string;
  launchUrl: string;
  type: "OIDC" | "SAML";
}

// Group-filtered launchpad list from iam-tenant-svc's MyAppsController --
// see that controller's doc comment for the visibility rule (ADMIN sees
// everything, a regular user only sees apps assigned to their own group).
// Replaces this page's old client-side merge of listClients()+listSamlSps().
export async function listMyApps(tenantId: string, sessionToken: string, correlationId: string): Promise<MyAppTile[]> {
  const result = await getJson<MyAppTile[]>(
    `${config.tenantSvcUrl}/api/v1/my-apps?tenantId=${encodeURIComponent(tenantId)}`,
    { correlationId, timeoutMs: config.defaultTimeoutMs, headers: { "X-Session-Token": sessionToken } },
  );
  return result ?? [];
}
