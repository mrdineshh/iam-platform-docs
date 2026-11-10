import { config } from "./config";
import { http, UpstreamError } from "./http";

export interface GoogleWorkspaceConfig {
  tenantId: string;
  domain: string;
  adminEmail: string;
  orgUnitPath: string | null;
  configured: boolean;
  createdAt: string;
}

export async function getGoogleWorkspaceConfig(tenantId: string, sessionToken: string): Promise<GoogleWorkspaceConfig | null> {
  try {
    return await http.get<GoogleWorkspaceConfig>(
      `${config.tenantSvcUrl}/api/v1/google-workspace-config?tenantId=${encodeURIComponent(tenantId)}`,
      { sessionToken },
    );
  } catch (err) {
    if (err instanceof UpstreamError && err.status === 404) return null;
    throw err;
  }
}

export interface OrgUnitReportUser {
  primaryEmail: string;
  fullName: string | null;
  orgUnitPath: string | null;
  suspended: boolean;
}

export interface OrgUnitReport {
  orgUnitPath: string;
  users: OrgUnitReportUser[];
}

// Read-only, live-fetched every call -- changes nothing in Google or in IAM. See
// GoogleWorkspaceDirectoryReportService's doc comment (iam-tenant-svc).
export function getOrganizationalUnits(tenantId: string, sessionToken: string): Promise<OrgUnitReport[]> {
  return http.get<OrgUnitReport[]>(
    `${config.tenantSvcUrl}/api/v1/google-workspace-config/organizational-units?tenantId=${encodeURIComponent(tenantId)}`,
    { sessionToken },
  );
}

export interface OuProvisionResult {
  orgUnitPath: string;
  groupName: string;
  // Already had an IAM account -- their group was set to match this OU, nothing else touched.
  matched: string[];
  // Had no IAM account -- one was created, 2FA enrolled, pushed to every connected app, and emailed
  // their address, a temporary password, and a QR code.
  created: string[];
  // Account was created (as above), but the email itself failed to send -- hand them their
  // credentials another way; nothing was rolled back.
  createdButEmailFailed: string[];
}

// The only action on the Organizational units page that writes anything. See
// GoogleWorkspaceOuProvisioningService's doc comment (iam-tenant-svc) for exactly what it does and
// doesn't touch. Long timeout: may create, enroll and email several people in one call.
export function syncOrganizationalUnit(tenantId: string, orgUnitPath: string, sessionToken: string): Promise<OuProvisionResult> {
  return http.post<OuProvisionResult>(
    `${config.tenantSvcUrl}/api/v1/google-workspace-config/organizational-units/sync`,
    { tenantId, orgUnitPath },
    { sessionToken, timeoutMs: 120_000 },
  );
}

export interface GroupPushResult {
  groupName: string;
  orgUnitPath: string;
  // Whether the OU had to be created -- false means one with this name already existed in Google.
  created: boolean;
  // Current group members successfully moved into the OU.
  moved: string[];
  // Current group members that could NOT be moved -- no matching Google account on this domain.
  skipped: string[];
}

// The reverse of syncOrganizationalUnit: pushes an IAM group INTO Google as an OU. See
// GoogleWorkspaceGroupPushService's doc comment (iam-tenant-svc) -- never creates a Google account,
// never removes anyone from the OU later just because they left the group.
export function pushGroupToOrgUnit(tenantId: string, groupId: string, sessionToken: string): Promise<GroupPushResult> {
  return http.post<GroupPushResult>(
    `${config.tenantSvcUrl}/api/v1/google-workspace-config/groups/${groupId}/push-to-org-unit?tenantId=${encodeURIComponent(tenantId)}`,
    {},
    { sessionToken, timeoutMs: 60_000 },
  );
}

export async function setGoogleWorkspaceConfig(
  tenantId: string,
  domain: string,
  adminEmail: string,
  orgUnitPath: string,
  serviceAccountJson: string,
  sessionToken: string,
): Promise<GoogleWorkspaceConfig> {
  return http.put<GoogleWorkspaceConfig>(
    `${config.tenantSvcUrl}/api/v1/google-workspace-config`,
    { tenantId, domain, adminEmail, orgUnitPath: orgUnitPath || undefined, serviceAccountJson },
    { sessionToken },
  );
}
