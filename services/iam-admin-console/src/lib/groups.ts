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

// Unassigns any members and clears the group's app access first (see
// iam-tenant-svc's GroupController.deleteGroup), then removes the group.
export async function deleteGroup(tenantId: string, groupId: string, sessionToken: string): Promise<void> {
  await http.delete(
    `${config.tenantSvcUrl}/api/v1/admin/groups/${groupId}?tenantId=${encodeURIComponent(tenantId)}`,
    { sessionToken },
  );
}

// Separate from deleteGroup above -- deleting the IAM group never touches Google on its own. This is
// the explicit cleanup step for the matching Google OU (see GroupController.deleteGroupOrgUnit).
// Google refuses to delete a non-empty OU -- that comes back as a normal error from this call.
export async function deleteGroupOrgUnit(tenantId: string, groupId: string, sessionToken: string): Promise<void> {
  await http.delete(
    `${config.tenantSvcUrl}/api/v1/admin/groups/${groupId}/org-unit?tenantId=${encodeURIComponent(tenantId)}`,
    { sessionToken },
  );
}
