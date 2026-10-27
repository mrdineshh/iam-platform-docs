// Mirrors iam-auth-svc's AuthErrorCode enum -- same duplication as
// iam-login-portal's src/lib/errorCodes.ts (kept in sync by hand, no
// shared package across services or frontends).
export function denialMessage(errorCode: string | undefined, fallback: string): string {
  switch (errorCode) {
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
      return "No authenticator device is enrolled for this account.";
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
