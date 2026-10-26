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
