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
): Promise<CreatedUser> {
  return http.post<CreatedUser>(
    `${config.tenantSvcUrl}/api/v1/admin/users`,
    { tenantId, email, displayName, password, role },
    { sessionToken },
  );
}
