import { config } from "./config";
import { http } from "./http";

export interface OidcClient {
  clientId: string;
  tenantId: string;
  name: string;
  redirectUris: string[];
  launchUrl: string | null;
  createdAt: string;
}

export interface CreatedOidcClient extends OidcClient {
  clientSecret: string;
}

export async function listClients(tenantId: string, sessionToken: string): Promise<OidcClient[]> {
  return http.get<OidcClient[]>(
    `${config.tenantSvcUrl}/api/v1/oidc-clients?tenantId=${encodeURIComponent(tenantId)}`,
    { sessionToken },
  );
}

export async function createClient(
  tenantId: string,
  name: string,
  redirectUris: string[],
  sessionToken: string,
  launchUrl?: string,
): Promise<CreatedOidcClient> {
  return http.post<CreatedOidcClient>(
    `${config.tenantSvcUrl}/api/v1/oidc-clients`,
    { tenantId, name, redirectUris, launchUrl: launchUrl || undefined },
    { sessionToken },
  );
}
