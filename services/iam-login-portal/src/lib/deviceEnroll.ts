import { config } from "./config";
import { postJson } from "./http";

// Endpoint agent enrollment handoff (Endpoint Device Trust spec Section 6.1 steps 3-4). The agent
// opens the system browser at /device-enroll; this service, holding the browser's SSO session,
// starts the enrollment server-side and redirects back to the agent's loopback listener with only
// a short-lived, single-use, key-bound transaction -- never the session token itself.

export const POST_LOGIN_NEXT_COOKIE = "iam_post_login_next";
export const POST_LOGIN_NEXT_MAX_AGE_SECONDS = 10 * 60;

/**
 * RFC 8252 Section 7.3: only a loopback IP literal, plain http, an explicit port, and this exact
 * path. Everything else is rejected -- this is what keeps /device-enroll from becoming an open
 * redirect that could hand an enrollment transaction to an arbitrary host. "localhost" is
 * deliberately NOT accepted (RFC 8252 Section 8.3: it can be resolved to a non-loopback address).
 */
export function parseLoopbackRedirectUri(raw: string | null): URL | null {
  if (!raw || raw.length > 200) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  const loopbackHost = url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (
    url.protocol !== "http:" ||
    !loopbackHost ||
    !url.port ||
    url.pathname !== "/callback" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.username !== "" ||
    url.password !== ""
  ) {
    return null;
  }
  return url;
}

/** base64url (no padding) SHA-256 -- always exactly 43 characters. See DeviceKeyThumbprint.kt. */
export function isValidKeyThumbprint(raw: string | null): raw is string {
  return !!raw && /^[A-Za-z0-9_-]{43}$/.test(raw);
}

/** Opaque CSRF value the agent checks on its own loopback listener; echoed back untouched. */
export function isValidState(raw: string | null): raw is string {
  return !!raw && /^[A-Za-z0-9_-]{16,128}$/.test(raw);
}

/**
 * The only post-login destination this service will ever honour from the
 * iam_post_login_next cookie: a same-origin /device-enroll URL. Anything else (absolute URLs,
 * protocol-relative "//evil", other paths) is ignored, so the cookie can't be abused as an open
 * redirect even if an attacker manages to plant it.
 */
export function safePostLoginNext(raw: string | undefined): string | null {
  if (!raw) return null;
  if (!raw.startsWith("/device-enroll?") || raw.startsWith("//") || raw.includes("\\")) return null;
  return raw;
}

export interface EnrollmentAuthorization {
  enrollmentTransactionId: string;
  nonce: string;
  expiresAt: string;
}

/** Server-to-server call to iam-tenant-svc's DeviceController.startEnrollment. */
export async function startDeviceEnrollment(
  sessionToken: string,
  keyThumbprint: string,
  correlationId: string,
): Promise<EnrollmentAuthorization> {
  return postJson<EnrollmentAuthorization>(
    `${config.tenantSvcUrl}/api/v1/endpoint/enrollment/start`,
    { keyThumbprint },
    { correlationId, timeoutMs: config.defaultTimeoutMs, headers: { "X-Session-Token": sessionToken } },
  );
}

export function loopbackCallbackUrl(redirectUri: URL, params: Record<string, string>): string {
  const target = new URL(redirectUri.toString());
  for (const [key, value] of Object.entries(params)) target.searchParams.set(key, value);
  return target.toString();
}
