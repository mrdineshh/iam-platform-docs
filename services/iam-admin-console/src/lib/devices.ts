import { config } from "./config";
import { http } from "./http";

// Mirrors iam-tenant-svc's DeviceSummaryResponse (DeviceTrustDtos.kt).
export interface DeviceSummary {
  id: string;
  tenantId: string;
  userId: string;
  hostname: string | null;
  platform: string;
  ownership: "CORPORATE" | "BYOD";
  lifecycleStatus:
    | "UNREGISTERED" | "AUTHENTICATION_PENDING" | "PENDING_APPROVAL" | "APPROVED"
    | "NON_COMPLIANT" | "SUSPENDED" | "REJECTED" | "REVOKED" | "DECOMMISSIONED";
  agentVersion: string | null;
  lastSeenAt: string | null;
  postureStatus: "COMPLIANT" | "NON_COMPLIANT" | "UNKNOWN" | null;
  // What the agent last reported and the server's verdict on it. All empty/null until the first report.
  postureRiskScore: number | null;
  postureEvaluatedAt: string | null;
  postureReasons: string[];
  postureSignals: PostureSignals | null;
  certificateStatus: "ACTIVE" | "EXPIRED" | "REVOKED" | null;
  createdAt: string;
}

// Mirrors iam-tenant-svc's PostureSignals. A tri-state is "ENABLED", "DISABLED", or anything else (unknown).
export interface PostureSignals {
  osName?: string | null;
  osVersion?: string | null;
  osBuild?: string | null;
  diskEncryption?: string | null;
  antivirus?: string | null;
  antivirusProduct?: string | null;
  firewall?: string | null;
  tpmPresent?: string | null;
  secureBoot?: string | null;
  lastHotfixDate?: string | null;
  collectedAt?: number | null;
}

/** Endpoint Device Trust spec Section 13: the admin console's device inventory. */
export function listDevices(tenantId: string, sessionToken: string): Promise<DeviceSummary[]> {
  return http.get<DeviceSummary[]>(
    `${config.tenantSvcUrl}/api/v1/endpoint/devices?tenantId=${encodeURIComponent(tenantId)}`,
    { sessionToken },
  );
}

async function deviceAction(tenantId: string, deviceId: string, action: string, sessionToken: string, reason?: string): Promise<void> {
  await http.post<void>(
    `${config.tenantSvcUrl}/api/v1/endpoint/devices/${deviceId}/${action}?tenantId=${encodeURIComponent(tenantId)}`,
    reason ? { reason } : {},
    { sessionToken },
  );
}

export const approveDevice = (tenantId: string, deviceId: string, sessionToken: string, reason?: string) =>
  deviceAction(tenantId, deviceId, "approve", sessionToken, reason);

export const rejectDevice = (tenantId: string, deviceId: string, sessionToken: string, reason?: string) =>
  deviceAction(tenantId, deviceId, "reject", sessionToken, reason);

export const suspendDevice = (tenantId: string, deviceId: string, sessionToken: string, reason?: string) =>
  deviceAction(tenantId, deviceId, "suspend", sessionToken, reason);

// Revocation also kills the device's certificate in OpenBao and (via the PEP's continuous
// enforcement check) any live session bound to this device on its very next request -- not
// just a future-logins block. See DeviceTrustService.revoke's own doc comment.
export const revokeDevice = (tenantId: string, deviceId: string, sessionToken: string, reason?: string) =>
  deviceAction(tenantId, deviceId, "revoke", sessionToken, reason);

// Mirrors iam-tenant-svc's DeviceEventResponse: one entry of a device's activity timeline (newest first).
export interface DeviceEvent {
  eventType: string;
  severity: "INFO" | "WARNING" | "CRITICAL";
  metadataJson: string | null;
  occurredAt: string;
}

export function listDeviceEvents(tenantId: string, deviceId: string, sessionToken: string): Promise<DeviceEvent[]> {
  return http.get<DeviceEvent[]>(
    `${config.tenantSvcUrl}/api/v1/endpoint/devices/${deviceId}/events?tenantId=${encodeURIComponent(tenantId)}`,
    { sessionToken },
  );
}
