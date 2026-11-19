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
  identity: DeviceIdentityDetails | null;
  // Present only while an admin's compliance exception is in force.
  complianceExceptionUntil: string | null;
  complianceExceptionReason: string | null;
  complianceExceptionBy: string | null;
}

// Spec Section 5.1 layers; `id` above is the immutable platform device_id.
export interface DeviceIdentityDetails {
  agentInstanceId: string;
  fingerprintVersion: number | null;
  fingerprintHash: string | null;
  manufacturer: string | null;
  model: string | null;
  osVersion: string | null;
  keyAlgorithm: string | null;
  keyAssuranceLevel: string | null;
  keyCreatedAt: string | null;
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

/**
 * Takes the device out of service (status Decommissioned). Nothing is deleted: its history is kept, and the
 * laptop can enrol afresh afterwards.
 */
export const decommissionDevice = (tenantId: string, deviceId: string, sessionToken: string, reason?: string) =>
  deviceAction(tenantId, deviceId, "decommission", sessionToken, reason);

/**
 * Lets one approved device open trusted-device apps for `days` (1-30) even though it fails the required security
 * checks. The reason is mandatory and is kept on the device and in the audit trail.
 */
export async function grantComplianceException(
  tenantId: string, deviceId: string, days: number, reason: string, sessionToken: string,
): Promise<void> {
  await http.post<void>(
    `${config.tenantSvcUrl}/api/v1/endpoint/devices/${deviceId}/compliance-exception?tenantId=${encodeURIComponent(tenantId)}`,
    { days, reason },
    { sessionToken },
  );
}

export const removeComplianceException = (tenantId: string, deviceId: string, sessionToken: string) =>
  deviceAction(tenantId, deviceId, "compliance-exception/remove", sessionToken);

/** Platform-level sign-in rule: whether this tenant only lets people sign in from an approved, compliant laptop. Off by default. */
export async function getLoginRule(tenantId: string, sessionToken: string): Promise<boolean> {
  const r = await http.get<{ requireTrustedDevice: boolean }>(
    `${config.tenantSvcUrl}/api/v1/endpoint/login-rule?tenantId=${encodeURIComponent(tenantId)}`,
    { sessionToken },
  );
  return r.requireTrustedDevice;
}

export async function setLoginRule(tenantId: string, required: boolean, sessionToken: string): Promise<void> {
  await http.put<unknown>(
    `${config.tenantSvcUrl}/api/v1/endpoint/login-rule?tenantId=${encodeURIComponent(tenantId)}`,
    { requireTrustedDevice: required },
    { sessionToken },
  );
}

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
