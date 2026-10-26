import { config } from "./config";
import { http } from "./http";

export interface Enroll2faResult {
  deviceId: string;
  status: "PENDING";
  totpSecret: string;
  provisioningUri: string;
}

export interface Verify2faResult {
  valid: boolean;
  status: string;
}

/**
 * Proxies through iam-tenant-svc's new session-gated /api/v1/me/2fa/*
 * (iam-device-svc itself is mTLS-only inbound). The caller's own session
 * identifies which user/tenant this enrolls -- there's no userId param,
 * you can only ever enroll your own device this way.
 */
export async function enrollMy2fa(sessionToken: string): Promise<Enroll2faResult> {
  return http.post<Enroll2faResult>(`${config.tenantSvcUrl}/api/v1/me/2fa/enroll`, {}, { sessionToken });
}

export async function verifyMy2fa(code: string, sessionToken: string): Promise<Verify2faResult> {
  return http.post<Verify2faResult>(`${config.tenantSvcUrl}/api/v1/me/2fa/verify`, { code }, { sessionToken });
}
