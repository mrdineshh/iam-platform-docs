import { config } from "./config";
import { http } from "./http";

export interface Group {
  id: string;
  tenantId: string;
  name: string;
  createdAt: string;
}

export async function listGroups(tenantId: string, sessionToken: string): Promise<Group[]> {
  return http.get<Group[]>(`${config.tenantSvcUrl}/api/v1/admin/groups?tenantId=${encodeURIComponent(tenantId)}`, {
    sessionToken,
  });
}

export async function createGroup(tenantId: string, name: string, sessionToken: string): Promise<Group> {
  return http.post<Group>(`${config.tenantSvcUrl}/api/v1/admin/groups`, { tenantId, name }, { sessionToken });
}

export async function assignUserToGroup(
  tenantId: string,
  userId: string,
  groupId: string | null,
  sessionToken: string,
): Promise<void> {
  await http.patch(
    `${config.tenantSvcUrl}/api/v1/admin/groups/members/${userId}?tenantId=${encodeURIComponent(tenantId)}`,
    { groupId },
    { sessionToken },
  );
}
