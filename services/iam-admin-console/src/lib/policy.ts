import { config } from "./config";
import { http, UpstreamError } from "./http";

export type PolicyScope = "TENANT" | "OU" | "USER";

export interface Policy {
  id: string;
  tenantId: string;
  scope: PolicyScope;
  scopeId: string;
  allowedCountries: string[] | null;
  allowedCountriesHardCap: boolean;
  blockedCountries: string[] | null;
  blockedCountriesHardCap: boolean;
  allowedCidrs: string[] | null;
  allowedCidrsHardCap: boolean;
  blockedCidrs: string[] | null;
  blockedCidrsHardCap: boolean;
  mfaRequired: boolean | null;
  mfaRequiredHardCap: boolean;
  totpReenrollEveryLogin: boolean | null;
  totpReenrollEveryLoginHardCap: boolean;
  updatedAt: string;
}

export interface PutPolicyRequest {
  tenantId: string;
  scope: PolicyScope;
  scopeId?: string;
  allowedCountries?: string[] | null;
  allowedCountriesHardCap?: boolean;
  blockedCountries?: string[] | null;
  blockedCountriesHardCap?: boolean;
  allowedCidrs?: string[] | null;
  allowedCidrsHardCap?: boolean;
  blockedCidrs?: string[] | null;
  blockedCidrsHardCap?: boolean;
  mfaRequired?: boolean | null;
  mfaRequiredHardCap?: boolean;
  totpReenrollEveryLogin?: boolean | null;
  totpReenrollEveryLoginHardCap?: boolean;
}

/** Returns null if nothing is stored yet at this exact scope (404) -- a normal, expected state, not an error. */
export async function getPolicy(
  tenantId: string,
  scope: PolicyScope,
  scopeId: string | undefined,
  sessionToken: string,
): Promise<Policy | null> {
  const params = new URLSearchParams({ tenantId, scope });
  if (scopeId) params.set("scopeId", scopeId);
  try {
    return await http.get<Policy>(`${config.policySvcUrl}/api/v1/policies?${params}`, { sessionToken });
  } catch (err) {
    if (err instanceof UpstreamError && err.status === 404) return null;
    throw err;
  }
}

export async function putPolicy(request: PutPolicyRequest, sessionToken: string): Promise<Policy> {
  return http.put<Policy>(`${config.policySvcUrl}/api/v1/policies`, request, { sessionToken });
}
