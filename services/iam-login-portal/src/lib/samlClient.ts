import { config } from "./config";
import { postJson } from "./http";

export interface SamlCompleteRequest {
  sessionToken: string;
  samlRequestId: string;
}

export interface SamlCompleteResponse {
  acsUrl: string;
  samlResponse: string;
  relayState: string | null;
}

/**
 * Calls POST /saml/complete on iam-oidcprovider-svc -- the SAML
 * counterpart to oidcClient.ts's completeAuthorization. Server-to-server
 * only, same reasoning: the session token never reaches the browser.
 */
export async function completeSamlAuthorization(
  request: SamlCompleteRequest,
  correlationId: string,
): Promise<SamlCompleteResponse> {
  return postJson<SamlCompleteResponse>(`${config.oidcProviderSvcUrl}/saml/complete`, request, {
    correlationId,
    timeoutMs: config.defaultTimeoutMs,
  });
}
