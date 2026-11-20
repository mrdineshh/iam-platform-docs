import { config } from "./config";
import { postJson } from "./http";
import type { DeviceProof } from "./deviceProof";
import type { IpPreview } from "./earlyIpCheck";

export interface LoginRequest {
  tenantId: string;
  email: string;
  password: string;
  sourceIp: string;
  // The person's browser User-Agent: this service's own request to iam-auth-svc carries the portal's.
  userAgent?: string;
  totpCode?: string;
  // Device-bound sign-in: only ever present when the endpoint agent on this laptop signed a platform challenge.
  deviceProof?: DeviceProof;
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
  userAgent?: string;
  // Lets the platform's "authorised laptop to sign in" rule answer at the password step instead of after the code.
  deviceProof?: DeviceProof;
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
 * The early location check for the email step (/internal/login/ip-preview on iam-auth-svc): would the tenant's country and IP rules
 * let this person in from this address? Internal-only (404 through the public proxy). Null on ANY failure: a problem here must only
 * ever mean "show nothing", because the real check is made after the password.
 */
export async function previewIp(
  request: { tenantId: string; email: string; sourceIp: string; userAgent?: string },
  correlationId: string,
): Promise<IpPreview | null> {
  try {
    return await postJson<IpPreview>(`${config.authSvcUrl}/internal/login/ip-preview`, request, { correlationId, timeoutMs: 4000 });
  } catch {
    return null;
  }
}

/**
 * The sign-in used to register a new laptop (/internal/login/enrollment on iam-auth-svc): the same checks as `login`, except
 * the tenant's "authorised laptop to sign in" rule, because the laptop does not exist yet. That route answers 404 to anything
 * that came through the public proxy. The session it returns must only ever be used server-side to start the enrollment and
 * then ended -- never put in a cookie (see finishEnrollmentSignIn in app/login/actions.ts).
 */
export async function loginForEnrollment(request: LoginRequest, correlationId: string): Promise<LoginResponse> {
  const timeoutMs = request.totpCode ? config.defaultTimeoutMs : config.pushWaitTimeoutMs;
  return postJson<LoginResponse>(`${config.authSvcUrl}/internal/login/enrollment`, request, { correlationId, timeoutMs });
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

/** The password step of the enrollment sign-in: exempt from the "authorised laptop" rule, like `loginForEnrollment`. */
export async function precheckForEnrollment(request: PrecheckRequest, correlationId: string): Promise<PrecheckResponse> {
  return postJson<PrecheckResponse>(`${config.authSvcUrl}/internal/login/precheck-enrollment`, request, {
    correlationId,
    timeoutMs: config.defaultTimeoutMs,
  });
}
