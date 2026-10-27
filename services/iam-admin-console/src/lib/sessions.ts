import { config } from "./config";
import { http } from "./http";

export interface SessionSummary {
  sessionId: string;
  sourceIp: string | null;
  deviceId: string | null;
  issuedAt: string;
  expiresAt: string;
  current: boolean;
}

const base = () => config.tenantSvcUrl;

// ---- Admin: any user in the tenant ----

export function listUserSessions(tenantId: string, userId: string, sessionToken: string): Promise<SessionSummary[]> {
  return http.get<SessionSummary[]>(
    `${base()}/api/v1/admin/users/${userId}/sessions?tenantId=${encodeURIComponent(tenantId)}`,
    { sessionToken },
  );
}

export function revokeUserSession(tenantId: string, userId: string, sessionId: string, sessionToken: string): Promise<void> {
  return http.delete<void>(
    `${base()}/api/v1/admin/users/${userId}/sessions/${sessionId}?tenantId=${encodeURIComponent(tenantId)}`,
    { sessionToken },
  );
}

export function revokeAllUserSessions(
  tenantId: string,
  userId: string,
  sessionToken: string,
): Promise<{ revoked: number }> {
  return http.delete<{ revoked: number }>(
    `${base()}/api/v1/admin/users/${userId}/sessions?tenantId=${encodeURIComponent(tenantId)}`,
    { sessionToken },
  );
}

// ---- Self-service ----

export function listMySessions(sessionToken: string): Promise<SessionSummary[]> {
  return http.get<SessionSummary[]>(`${base()}/api/v1/me/sessions`, { sessionToken });
}

export function revokeMySession(sessionId: string, sessionToken: string): Promise<void> {
  return http.delete<void>(`${base()}/api/v1/me/sessions/${sessionId}`, { sessionToken });
}

export function revokeMyOtherSessions(sessionToken: string): Promise<{ revoked: number }> {
  return http.delete<{ revoked: number }>(`${base()}/api/v1/me/sessions`, { sessionToken });
}
