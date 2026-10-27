// Mirrors iam-auth-svc's AuthErrorCode enum (added for this module -- see
// contracts/iam-auth-svc.yaml, docs/DECISIONS.md Service 13
// pre-implementation entry, resolved OQ-3). Kept as a plain string union,
// not imported from anywhere, since there's no shared type package across
// the Kotlin/TypeScript language boundary -- if iam-auth-svc's enum values
// ever change, this list must be updated to match (same coupling every
// other consumer of a published contract has).
export type AuthErrorCode =
  | "ACCOUNT_SUSPENDED"
  | "ACCOUNT_LOCKED"
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

/** Which of these codes belong on the TOTP field vs. the push button. */
export function isTotpError(errorCode: string | undefined): boolean {
  return errorCode === "TOTP_INVALID" || errorCode === "TOTP_LOCKED" || errorCode === "NO_SECOND_FACTOR_ENROLLED";
}

export function isPushError(errorCode: string | undefined): boolean {
  return errorCode === "PUSH_DENIED" || errorCode === "PUSH_TIMEOUT" || errorCode === "NO_PUSH_DEVICE_ENROLLED";
}
