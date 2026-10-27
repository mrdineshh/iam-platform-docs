import { config } from "./config";
import { http } from "./http";

export interface AdminUserListEntry {
  id: string;
  email: string;
  displayName: string;
  status: "ACTIVE" | "SUSPENDED";
  role: "ADMIN" | "USER";
  groupId: string | null;
  locked?: boolean;
  lockedUntil?: string | null;
  permanentlyLocked?: boolean;
}

export interface ImpersonateResult {
  token: string;
  sessionId: string;
  userId: string;
  email: string;
  displayName: string;
  role: "ADMIN" | "USER";
  expiresAt: string;
}

export async function listTenantUsers(tenantId: string, sessionToken: string): Promise<AdminUserListEntry[]> {
  return http.get<AdminUserListEntry[]>(
    `${config.tenantSvcUrl}/api/v1/admin/users?tenantId=${encodeURIComponent(tenantId)}`,
    { sessionToken },
  );
}

export async function impersonate(tenantId: string, targetUserId: string, sessionToken: string): Promise<ImpersonateResult> {
  return http.post<ImpersonateResult>(
    `${config.tenantSvcUrl}/api/v1/admin/impersonate`,
    { tenantId, targetUserId },
    { sessionToken },
  );
}
