import { config } from "./config";
import { postJson } from "./http";

export interface AuthorizeCompleteRequest {
  sessionToken: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
}

export interface AuthorizeCompleteResponse {
  redirectUri: string;
}

/**
 * Calls the new POST /authorize/complete on iam-oidcprovider-svc (added
 * for this module -- see docs/DECISIONS.md, Service 13 pre-implementation
 * entry, and docs/specs/iam-login-portal-SPEC.md Section 1.1). Server-to-
 * server only -- the session token never reaches the browser.
 */
export async function completeAuthorization(
  request: AuthorizeCompleteRequest,
  correlationId: string,
): Promise<AuthorizeCompleteResponse> {
  return postJson<AuthorizeCompleteResponse>(`${config.oidcProviderSvcUrl}/authorize/complete`, request, {
    correlationId,
    timeoutMs: config.defaultTimeoutMs,
  });
}
