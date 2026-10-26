import { config } from "./config";
import { http } from "./http";

export interface SamlSp {
  id: string;
  tenantId: string;
  name: string;
  spEntityId: string;
  acsUrl: string;
  launchUrl: string | null;
  createdAt: string;
}

export interface SamlIdpInfo {
  entityId: string;
  ssoUrl: string;
  certificatePem: string;
}

export async function listSamlSps(tenantId: string, sessionToken: string): Promise<SamlSp[]> {
  return http.get<SamlSp[]>(`${config.tenantSvcUrl}/api/v1/saml-sps?tenantId=${encodeURIComponent(tenantId)}`, { sessionToken });
}

export async function createSamlSp(
  tenantId: string,
  name: string,
  spEntityId: string,
  acsUrl: string,
  sessionToken: string,
  launchUrl?: string,
): Promise<SamlSp> {
  return http.post<SamlSp>(
    `${config.tenantSvcUrl}/api/v1/saml-sps`,
    { tenantId, name, spEntityId, acsUrl, launchUrl: launchUrl || undefined },
    { sessionToken },
  );
}

/** Our own IdP details -- what the admin pastes into the SP's (e.g. Google Workspace's) SSO config. */
export async function getSamlIdpInfo(sessionToken: string): Promise<SamlIdpInfo> {
  return http.get<SamlIdpInfo>(`${config.tenantSvcUrl}/api/v1/saml-idp-info`, { sessionToken });
}
