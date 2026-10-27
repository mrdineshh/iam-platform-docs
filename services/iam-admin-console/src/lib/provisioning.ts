import { config } from "./config";
import { http } from "./http";

/** Outcome for one downstream target (Google Workspace, or a SCIM-connected app) of one lifecycle change. */
export interface TargetResult {
  target: string;
  // created | linked | suspended | reactivated | deleted | unchanged | skipped | failed
  action: string;
  ok: boolean;
  error: string | null;
}

export interface ScimConnection {
  id: string;
  appKind: "OIDC" | "SAML";
  appId: string;
  appName: string;
  baseUrl: string;
  enabled: boolean;
  hasToken: boolean;
  accountsActive: number;
  accountsSuspended: number;
  accountsFailed: number;
}

export interface UserProvisioningStatus {
  connectionId: string;
  appName: string;
  state: "NOT_PROVISIONED" | "PENDING" | "ACTIVE" | "SUSPENDED";
  error: string | null;
  updatedAt: string | null;
}

const base = () => `${config.tenantSvcUrl}/api/v1/admin`;
const q = (tenantId: string) => `tenantId=${encodeURIComponent(tenantId)}`;

export function listScimConnections(tenantId: string, sessionToken: string): Promise<ScimConnection[]> {
  return http.get<ScimConnection[]>(`${base()}/provisioning/connections?${q(tenantId)}`, { sessionToken });
}

export function saveScimConnection(
  tenantId: string,
  appKind: "OIDC" | "SAML",
  appId: string,
  baseUrl: string,
  bearerToken: string,
  enabled: boolean,
  sessionToken: string,
): Promise<ScimConnection> {
  return http.put<ScimConnection>(
    `${base()}/provisioning/connections`,
    { tenantId, appKind, appId, baseUrl, bearerToken: bearerToken || undefined, enabled },
    { sessionToken },
  );
}

export function deleteScimConnection(tenantId: string, id: string, sessionToken: string): Promise<void> {
  return http.delete<void>(`${base()}/provisioning/connections/${id}?${q(tenantId)}`, { sessionToken });
}

export function testScimConnection(
  tenantId: string,
  id: string,
  sessionToken: string,
): Promise<{ ok: boolean; message: string }> {
  return http.post<{ ok: boolean; message: string }>(
    `${base()}/provisioning/connections/${id}/test?${q(tenantId)}`,
    {},
    { sessionToken, timeoutMs: 20_000 },
  );
}

export function syncScimConnection(
  tenantId: string,
  id: string,
  sessionToken: string,
): Promise<{ users: number; succeeded: number; failed: number }> {
  return http.post<{ users: number; succeeded: number; failed: number }>(
    `${base()}/provisioning/connections/${id}/sync?${q(tenantId)}`,
    {},
    { sessionToken, timeoutMs: 120_000 },
  );
}

export function getUserProvisioning(tenantId: string, userId: string, sessionToken: string): Promise<UserProvisioningStatus[]> {
  return http.get<UserProvisioningStatus[]>(`${base()}/users/${userId}/provisioning?${q(tenantId)}`, { sessionToken });
}

export function retryUserProvisioning(tenantId: string, userId: string, sessionToken: string): Promise<TargetResult[]> {
  return http.post<TargetResult[]>(`${base()}/users/${userId}/provisioning/retry?${q(tenantId)}`, {}, { sessionToken, timeoutMs: 60_000 });
}

const DONE: Record<string, string> = {
  created: "Created in",
  linked: "Linked in",
  suspended: "Suspended in",
  reactivated: "Reactivated in",
  deleted: "Deleted from",
};

/**
 * Turns per-target results into plain sentences for a toast: what was done
 * (grouped by action) and what failed (with the app's own error). "unchanged"
 * and "skipped" are not worth mentioning.
 */
export function summarizeTargets(targets: TargetResult[] | undefined | null): { done: string | null; problems: string[] } {
  const list = targets ?? [];
  const groups = new Map<string, string[]>();
  for (const t of list) {
    if (!t.ok || !DONE[t.action]) continue;
    groups.set(t.action, [...(groups.get(t.action) ?? []), t.target]);
  }
  const done = [...groups.entries()].map(([action, names]) => `${DONE[action]} ${names.join(", ")}`).join(". ");
  const problems = list.filter((t) => !t.ok).map((t) => `${t.target}: ${t.error ?? "failed"}`);
  return { done: done || null, problems };
}
