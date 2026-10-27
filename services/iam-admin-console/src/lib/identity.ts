import { config } from "./config";
import { http } from "./http";
import type { TargetResult } from "./provisioning";

export interface CreatedUser {
  id: string;
  tenantId: string;
  email: string;
  displayName: string;
  role: "ADMIN" | "USER";
  totpSecret: string;
  provisioningUri: string;
  googleWorkspaceProvisioned: boolean;
  googleWorkspaceError: string | null;
  // One entry per SCIM-connected app the new user was pushed to.
  appProvisioning: TargetResult[];
}

/**
 * Proxies through iam-tenant-svc's new admin-gated /api/v1/admin/users
 * (iam-identity-svc itself is mTLS-only inbound, unreachable from a
 * browser SPA).
 */
export async function createUser(
  tenantId: string,
  email: string,
  displayName: string,
  password: string,
  role: "ADMIN" | "USER",
  sessionToken: string,
  createInGoogleWorkspace: boolean = true,
): Promise<CreatedUser> {
  return http.post<CreatedUser>(
    `${config.tenantSvcUrl}/api/v1/admin/users`,
    { tenantId, email, displayName, password, role, createInGoogleWorkspace },
    // Longer than the default: creating a user also contacts Google and each connected app.
    { sessionToken, timeoutMs: 60_000 },
  );
}

// FR-3.5: clears a lockout (temporary or permanent) so the user can sign in again.
export async function unlockUser(tenantId: string, userId: string, sessionToken: string): Promise<void> {
  await http.post<void>(
    `${config.tenantSvcUrl}/api/v1/admin/users/${userId}/unlock?tenantId=${encodeURIComponent(tenantId)}`,
    {},
    { sessionToken },
  );
}

export interface DeletedUser {
  id: string;
  googleWorkspaceDeleted: boolean;
  googleWorkspaceError: string | null;
  appProvisioning: TargetResult[];
}

export interface LifecycleResult {
  userId: string;
  status: "ACTIVE" | "SUSPENDED";
  sessionsEnded: number;
  // Google Workspace and each SCIM-connected app.
  targets: TargetResult[];
}

// Suspends the user here (signed out immediately, cannot sign in) and in Google
// Workspace and every SCIM-connected app. Downstream failures come back per
// target; they never undo the suspension.
export function suspendUser(tenantId: string, userId: string, sessionToken: string): Promise<LifecycleResult> {
  return http.post<LifecycleResult>(
    `${config.tenantSvcUrl}/api/v1/admin/users/${userId}/suspend?tenantId=${encodeURIComponent(tenantId)}`,
    {},
    { sessionToken, timeoutMs: 60_000 },
  );
}

export function reactivateUser(tenantId: string, userId: string, sessionToken: string): Promise<LifecycleResult> {
  return http.post<LifecycleResult>(
    `${config.tenantSvcUrl}/api/v1/admin/users/${userId}/reactivate?tenantId=${encodeURIComponent(tenantId)}`,
    {},
    { sessionToken, timeoutMs: 60_000 },
  );
}

// "Deleted from everywhere" (2026-10-26) -- also deletes the matching
// Google Workspace account if one exists; connected-app access is cut off
// separately by iam-enforcement-svc's own identity check.
export async function deleteUser(tenantId: string, userId: string, sessionToken: string): Promise<DeletedUser> {
  return http.delete<DeletedUser>(
    `${config.tenantSvcUrl}/api/v1/admin/users/${userId}?tenantId=${encodeURIComponent(tenantId)}`,
    { sessionToken, timeoutMs: 60_000 },
  );
}
