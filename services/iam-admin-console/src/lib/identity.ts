import { config } from "./config";
import { http } from "./http";

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
    { sessionToken },
  );
}

export interface DeletedUser {
  id: string;
  googleWorkspaceDeleted: boolean;
  googleWorkspaceError: string | null;
}

// "Deleted from everywhere" (2026-10-26) -- also deletes the matching
// Google Workspace account if one exists; connected-app access is cut off
// separately by iam-enforcement-svc's own identity check.
export async function deleteUser(tenantId: string, userId: string, sessionToken: string): Promise<DeletedUser> {
  return http.delete<DeletedUser>(
    `${config.tenantSvcUrl}/api/v1/admin/users/${userId}?tenantId=${encodeURIComponent(tenantId)}`,
    { sessionToken },
  );
}
