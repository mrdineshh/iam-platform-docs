import { config } from "./config";
import { http } from "./http";

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

export interface PrecheckResponse {
  mfaRequired: boolean;
  enrollmentRequired: boolean;
  totpSecret?: string;
  provisioningUri?: string;
}

/**
 * Calls iam-auth-svc's single /login endpoint directly from the browser
 * (AP-1 -- same contract iam-login-portal uses, but without a server to
 * hide the call behind). sourceIp is caller-supplied -- see
 * lib/clientIp.ts's detectRealIp, which is how this SPA learns its own
 * real IP without a server of its own.
 */
export async function login(request: LoginRequest, intent: "totp" | "push" | "none"): Promise<LoginResponse> {
  const timeoutMs = intent === "push" ? config.pushWaitTimeoutMs : config.defaultTimeoutMs;
  return http.post<LoginResponse>(
    `${config.authSvcUrl}/api/v1/login`,
    {
      tenantId: request.tenantId,
      email: request.email,
      password: request.password,
      sourceIp: request.sourceIp,
      totpCode: intent === "totp" ? request.totpCode : undefined,
    },
    { timeoutMs },
  );
}

/**
 * Ends a session on the server, which also records the sign-out in the audit
 * log. Best-effort: signing out in this browser must never be blocked by it
 * (the session may already be gone, or the service briefly unreachable).
 */
export async function logout(sessionToken: string): Promise<void> {
  try {
    await http.post<void>(`${config.authSvcUrl}/api/v1/logout`, {}, { sessionToken, timeoutMs: 4000 });
  } catch {
    // Already ended, expired, or unreachable: the local sign-out still proceeds.
  }
}

/**
 * Read-only preflight, mirrors iam-login-portal's precheckAction -- lets
 * this page find out whether a code screen is needed at all, and if so
 * whether it's a first-time enrollment, without ever touching /login's
 * blocking push path.
 */
export async function precheck(request: Omit<LoginRequest, "totpCode">): Promise<PrecheckResponse> {
  return http.post<PrecheckResponse>(
    `${config.authSvcUrl}/api/v1/login/precheck`,
    {
      tenantId: request.tenantId,
      email: request.email,
      password: request.password,
      sourceIp: request.sourceIp,
    },
    { timeoutMs: config.defaultTimeoutMs },
  );
}
