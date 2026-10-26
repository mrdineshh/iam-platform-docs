import { config } from "./config";
import { http } from "./http";

// Shared by both app types' "/groups" endpoints -- see
// iam-tenant-svc's OidcClientController/SamlSpController and
// AppGroupDtos.kt. `kind` picks which path segment to call.
export type AppKind = "oidc-clients" | "saml-sps";

export async function getAppGroups(kind: AppKind, appId: string, tenantId: string, sessionToken: string): Promise<string[]> {
  const result = await http.get<{ groupIds: string[] }>(
    `${config.tenantSvcUrl}/api/v1/${kind}/${appId}/groups?tenantId=${encodeURIComponent(tenantId)}`,
    { sessionToken },
  );
  return result.groupIds;
}

export async function setAppGroups(
  kind: AppKind,
  appId: string,
  tenantId: string,
  groupIds: string[],
  sessionToken: string,
): Promise<void> {
  await http.put(
    `${config.tenantSvcUrl}/api/v1/${kind}/${appId}/groups?tenantId=${encodeURIComponent(tenantId)}`,
    { groupIds },
    { sessionToken },
  );
}
