import { config } from "./config";
import { getJson, postJson } from "./http";
import type { DeviceChallenge } from "./deviceProof";
import type { DevicePreview } from "./earlyDeviceCheck";

// Server-side calls to iam-tenant-svc's INTERNAL device sign-in routes (docs/specs/device-bound-signin-SPEC.md). They go
// straight to the container, not through the public proxy: tenant-svc answers 404 to anything that arrived through it.

/**
 * Does this tenant have any app that requires a trusted device? False on ANY failure, so a problem here can only ever
 * mean "behave exactly as before", never "block" or "slow down" the sign-in page.
 */
export async function deviceSignInRequired(tenantId: string, correlationId: string): Promise<boolean> {
  try {
    const result = await getJson<{ required?: boolean }>(
      `${config.tenantSvcUrl}/internal/device-challenges/required?tenantId=${encodeURIComponent(tenantId)}`,
      { correlationId, timeoutMs: 1500 },
    );
    return result?.required === true;
  } catch {
    return false;
  }
}

/**
 * The platform's early answer for the email step: would this tenant let THIS laptop sign in? Only the laptop's signed proof is
 * sent -- never the email. Null on any failure: a problem here must only ever mean "show nothing", since the real decision is
 * made after the password.
 */
export async function previewLoginDevice(
  tenantId: string,
  proof: { challengeId: string; deviceId: string; signature: string; origin: string } | undefined,
  correlationId: string,
): Promise<DevicePreview | null> {
  try {
    return await postJson<DevicePreview>(
      `${config.tenantSvcUrl}/internal/login-device-check/preview`,
      { tenantId, challengeId: proof?.challengeId, deviceId: proof?.deviceId, signature: proof?.signature, origin: proof?.origin },
      { correlationId, timeoutMs: 3000 },
    );
  } catch {
    return null;
  }
}

export async function issueDeviceChallenge(tenantId: string, correlationId: string): Promise<DeviceChallenge> {
  const result = await postJson<{ challengeId: string; nonce: string }>(
    `${config.tenantSvcUrl}/internal/device-challenges`,
    { tenantId },
    { correlationId, timeoutMs: 3000 },
  );
  return { challengeId: result.challengeId, nonce: result.nonce };
}
