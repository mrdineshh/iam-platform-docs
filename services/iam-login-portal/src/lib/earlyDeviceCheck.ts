import { denialMessage } from "./errorCodes";

/** What iam-tenant-svc's /internal/login-device-check/preview answers (see DeviceLoginRule.kt). */
export interface DevicePreview {
  ruleOn: boolean;
  authorised: boolean;
  code?: string | null;
  detail?: string | null;
}

/**
 * The sentence to show on the email step, or null when there is nothing to say: no answer, the tenant does not restrict
 * sign-in by laptop, or this laptop is authorised. It never blocks anything by itself -- only informs. The real decision is
 * taken after the password, where an administrator's exemption is known.
 */
export function earlyDeviceNotice(preview: DevicePreview | null | undefined): string | null {
  if (!preview || !preview.ruleOn || preview.authorised) return null;
  return denialMessage(preview.code ?? "DEVICE_REQUIRED", "You are not authorised to sign in from this device.");
}
