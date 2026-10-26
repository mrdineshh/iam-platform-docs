import { config } from "./config";
import { postJson } from "./http";

export interface LoginRequest {
  tenantId: string;
  email: string;
  password: string;
  sourceIp: string;
  totpCode?: string;
}

export interface LoginResponse {
  // Absent exactly when enrollmentRequired is true (first login, no active
  // 2FA device yet) -- see iam-auth-svc's AuthService.login.
  token?: string;
  sessionId?: string;
  expiresAt?: string;
  role?: string;
  enrollmentRequired?: boolean;
  totpSecret?: string;
  provisioningUri?: string;
}

export interface PrecheckRequest {
  tenantId: string;
  email: string;
  password: string;
  sourceIp: string;
}

export interface PrecheckResponse {
  mfaRequired: boolean;
  enrollmentRequired: boolean;
  totpSecret?: string;
  provisioningUri?: string;
}

/**
 * Calls iam-auth-svc's single /login endpoint directly (contracts/iam-auth-svc.yaml)
 * -- AP-1, one auth engine, no separate MFA endpoint. Omitting `totpCode`
 * makes this call itself block server-side in iam-auth-svc for up to 60s
 * waiting on a push response, so the push path uses a longer timeout (see
 * config.pushWaitTimeoutMs) -- never the default.
 */
export async function login(request: LoginRequest, correlationId: string): Promise<LoginResponse> {
  const timeoutMs = request.totpCode ? config.defaultTimeoutMs : config.pushWaitTimeoutMs;
  return postJson<LoginResponse>(`${config.authSvcUrl}/api/v1/login`, request, { correlationId, timeoutMs });
}

/**
 * Read-only preflight used by the login wizard's password step: finds out
 * whether a code screen is needed at all, and if so whether this is a
 * first-time enrollment, WITHOUT ever touching /login's blocking push path.
 */
export async function precheck(request: PrecheckRequest, correlationId: string): Promise<PrecheckResponse> {
  return postJson<PrecheckResponse>(`${config.authSvcUrl}/api/v1/login/precheck`, request, {
    correlationId,
    timeoutMs: config.defaultTimeoutMs,
  });
}
