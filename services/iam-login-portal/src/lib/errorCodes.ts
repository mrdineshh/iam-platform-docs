// Mirrors iam-auth-svc's AuthErrorCode enum (added for this module -- see
// contracts/iam-auth-svc.yaml, docs/DECISIONS.md Service 13
// pre-implementation entry, resolved OQ-3). Kept as a plain string union,
// not imported from anywhere, since there's no shared type package across
// the Kotlin/TypeScript language boundary -- if iam-auth-svc's enum values
// ever change, this list must be updated to match (same coupling every
// other consumer of a published contract has).
import { UpstreamError } from "./http";

export type AuthErrorCode =
  | "ACCOUNT_SUSPENDED"
  | "ACCOUNT_LOCKED"
  | "APP_ACCESS_DENIED"
  | "LOCATION_UNVERIFIED"
  | "POLICY_UNAVAILABLE"
  | "POLICY_DENIED"
  | "NO_SECOND_FACTOR_ENROLLED"
  | "NO_PUSH_DEVICE_ENROLLED"
  | "SECOND_FACTOR_UNAVAILABLE"
  | "TOTP_INVALID"
  | "TOTP_LOCKED"
  | "PUSH_DENIED"
  | "PUSH_TIMEOUT";

/** User-facing copy per denial cause -- never the raw backend `message`. */
export function denialMessage(errorCode: string | undefined, fallback: string): string {
  switch (errorCode as AuthErrorCode | undefined) {
    case "ACCOUNT_SUSPENDED":
      return "This account has been suspended. Contact your administrator.";
    case "APP_ACCESS_DENIED":
      return "You don't have access to this app. Ask your administrator to add you to a group that includes it.";
    case "ACCOUNT_LOCKED":
      return "This account is locked after too many failed sign-in attempts. Try again later, or ask your administrator to unlock it.";
    case "LOCATION_UNVERIFIED":
      return "We couldn't verify your location. Please try again.";
    case "POLICY_UNAVAILABLE":
      return "Access policy could not be evaluated right now. Please try again shortly.";
    case "POLICY_DENIED":
      return "Sign-in isn't allowed from your current location or network.";
    case "NO_SECOND_FACTOR_ENROLLED":
      return "No authenticator device is enrolled for this account. Contact your administrator.";
    case "NO_PUSH_DEVICE_ENROLLED":
      return "No push-capable device is enrolled for this account. Try entering a code instead.";
    case "SECOND_FACTOR_UNAVAILABLE":
      return "Second-factor verification is temporarily unavailable. Please try again.";
    case "TOTP_INVALID":
      return "That code isn't correct. Please try again.";
    case "TOTP_LOCKED":
      return "Too many incorrect codes. Try again in a few minutes.";
    case "PUSH_DENIED":
      return "The sign-in request was denied on your device.";
    case "PUSH_TIMEOUT":
      return "No response was received on your device in time.";
    default:
      return fallback;
  }
}

/**
 * The sign-in worked, but the person's group has no access to this app
 * (iam-oidcprovider-svc answers 403 APP_ACCESS_DENIED when completing it).
 */
export function isAppAccessDenied(err: unknown): boolean {
  return err instanceof UpstreamError && err.status === 403 && err.errorCode === "APP_ACCESS_DENIED";
}

/**
 * Why an app refused a signed-in person, as one of a FIXED set of codes. The page never shows backend text (it travels in a
 * URL on the error path, and anyone can craft a URL), only the wording below.
 *
 * The device reasons are recognised from the phrases iam-tenant-svc's TrustedDeviceGate uses (DeviceLoginProof.kt).
 * Anything unrecognised -- including a plain group refusal -- falls back to the original group message, so a wording
 * change there can only make this page less specific, never wrong.
 */
export type AccessDenialReason =
  | "app_access_denied"
  | "device_required"
  | "device_unregistered"
  | "device_not_approved"
  | "device_noncompliant";

export const ACCESS_DENIAL_MESSAGES: Record<AccessDenialReason, string> = {
  app_access_denied: "You don't have access to this app. Ask your administrator to add you to a group that includes it.",
  device_required:
    "This app can only be opened from a managed laptop. Make sure the IAM endpoint agent is installed and running, allow the browser's request to access this device if it asks, then sign in again.",
  device_unregistered: "This app needs a registered laptop, and this one is no longer registered. Register it again with the IAM endpoint agent.",
  device_not_approved: "This app needs an approved laptop, and this one is not approved yet (or has been suspended). Ask your administrator.",
  device_noncompliant:
    "This app needs a laptop that passes the security checks, and this one does not (for example disk encryption is off). Your administrator can see which check failed.",
};

const DEVICE_PHRASES: Array<[string, AccessDenialReason]> = [
  ["needs a managed, approved device", "device_required"],
  ["no longer registered", "device_unregistered"],
  ["is not approved", "device_not_approved"],
  ["does not meet the security requirements", "device_noncompliant"],
];

export function accessDenialReason(err: unknown): AccessDenialReason {
  const message = err instanceof Error ? err.message : "";
  for (const [phrase, reason] of DEVICE_PHRASES) {
    if (message.includes(phrase)) return reason;
  }
  return "app_access_denied";
}

/** Only ever one of the fixed codes above; anything else is treated as the generic refusal. */
export function isAccessDenialReason(value: string | undefined): value is AccessDenialReason {
  return value !== undefined && Object.prototype.hasOwnProperty.call(ACCESS_DENIAL_MESSAGES, value);
}

/** Which of these codes belong on the TOTP field vs. the push button. */
export function isTotpError(errorCode: string | undefined): boolean {
  return errorCode === "TOTP_INVALID" || errorCode === "TOTP_LOCKED" || errorCode === "NO_SECOND_FACTOR_ENROLLED";
}

export function isPushError(errorCode: string | undefined): boolean {
  return errorCode === "PUSH_DENIED" || errorCode === "PUSH_TIMEOUT" || errorCode === "NO_PUSH_DEVICE_ENROLLED";
}
