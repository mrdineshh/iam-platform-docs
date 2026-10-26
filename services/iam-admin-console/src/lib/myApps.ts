import { config } from "./config";
import { http } from "./http";

export interface MyAppTile {
  id: string;
  name: string;
  launchUrl: string;
  type: "OIDC" | "SAML";
}

// Backs the launchpad -- group-filtered (and admin-sees-everything) list
// from iam-tenant-svc's MyAppsController, replacing the old client-side
// merge of listClients()+listSamlSps() here and in iam-login-portal.
export async function listMyApps(tenantId: string, sessionToken: string): Promise<MyAppTile[]> {
  return http.get<MyAppTile[]>(`${config.tenantSvcUrl}/api/v1/my-apps?tenantId=${encodeURIComponent(tenantId)}`, {
    sessionToken,
  });
}
