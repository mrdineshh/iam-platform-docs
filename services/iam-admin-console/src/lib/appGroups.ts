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

/** Turns "this app needs an approved, compliant enrolled laptop" on or off (iam-tenant-svc, `PUT /{id}/trusted-device`). */
export async function setRequireTrustedDevice(
  kind: AppKind,
  appId: string,
  tenantId: string,
  required: boolean,
  sessionToken: string,
): Promise<void> {
  await http.put(
    `${config.tenantSvcUrl}/api/v1/${kind}/${appId}/trusted-device?tenantId=${encodeURIComponent(tenantId)}`,
    { required },
    { sessionToken },
  );
}

/** Spec 6.4: may a laptop that is enrolled but still awaiting approval open this app? (`PUT /{id}/pending-device`) */
export async function setAllowPendingDevice(kind: AppKind, appId: string, tenantId: string, allowed: boolean, sessionToken: string): Promise<void> {
  await http.put(
    `${config.tenantSvcUrl}/api/v1/${kind}/${appId}/pending-device?tenantId=${encodeURIComponent(tenantId)}`,
    { allowed },
    { sessionToken },
  );
}
