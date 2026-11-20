import { denialMessage } from "./errorCodes";

/** What iam-auth-svc's /internal/login/ip-preview answers (see AuthService.ipPreview). */
export interface IpPreview {
  allowed: boolean;
  errorCode?: string | null;
  reason?: string | null;
}

/**
 * The sentence to show on the email screen when the tenant's location and network rules would refuse this address, or null
 * for "say nothing": no answer, or allowed. Uses the same wording as the refusal after the password, so a person sees one
 * message wherever it first appears. Unlike the laptop heads-up this one stops the person there: the rule applies to everyone,
 * administrators included, so there is nothing to step past.
 */
export function earlyIpNotice(preview: IpPreview | null | undefined): string | null {
  if (!preview || preview.allowed) return null;
  return denialMessage(preview.errorCode ?? "POLICY_DENIED", "Sign-in isn't allowed from your current location or network.");
}
