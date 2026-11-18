import { describe, expect, it } from "vitest";
import { denialMessage, isAppAccessDenied, isPushError, isTotpError, ACCESS_DENIAL_MESSAGES, accessDenialReason, isAccessDenialReason } from "./errorCodes";
import { UpstreamError } from "./http";

describe("denialMessage", () => {
  it("maps a known errorCode to its user-facing message, not the raw backend message", () => {
    expect(denialMessage("TOTP_LOCKED", "raw backend text")).not.toBe("raw backend text");
    expect(denialMessage("TOTP_LOCKED", "raw backend text")).toMatch(/incorrect codes/i);
  });

  it("falls back to the provided message for an unknown or missing errorCode", () => {
    expect(denialMessage(undefined, "fallback text")).toBe("fallback text");
    expect(denialMessage("SOMETHING_NEW", "fallback text")).toBe("fallback text");
  });
});

describe("isTotpError / isPushError", () => {
  it("classifies TOTP-path codes correctly", () => {
    expect(isTotpError("TOTP_INVALID")).toBe(true);
    expect(isTotpError("TOTP_LOCKED")).toBe(true);
    expect(isTotpError("PUSH_DENIED")).toBe(false);
  });

  it("classifies push-path codes correctly", () => {
    expect(isPushError("PUSH_DENIED")).toBe(true);
    expect(isPushError("PUSH_TIMEOUT")).toBe(true);
    expect(isPushError("TOTP_INVALID")).toBe(false);
  });
});

describe("app access denied", () => {
  it("has a clear message that tells the person what to do", () => {
    const message = denialMessage("APP_ACCESS_DENIED", "raw");
    expect(message).toContain("don't have access");
    expect(message).toContain("administrator");
  });

  it("recognizes only the 403 APP_ACCESS_DENIED answer from the provider", () => {
    expect(isAppAccessDenied(new UpstreamError(403, "no", "APP_ACCESS_DENIED"))).toBe(true);
    expect(isAppAccessDenied(new UpstreamError(403, "no", "POLICY_DENIED"))).toBe(false);
    expect(isAppAccessDenied(new UpstreamError(500, "boom", "APP_ACCESS_DENIED"))).toBe(false);
    expect(isAppAccessDenied(new Error("x"))).toBe(false);
    expect(isAppAccessDenied(null)).toBe(false);
  });
});

describe("which app refusal it was", () => {
  // The exact phrases iam-tenant-svc's TrustedDeviceGate sends (DeviceLoginProof.kt). If they change, these tests show it.
  const gate = {
    noDevice: "This app needs a managed, approved device. Install the endpoint agent on your laptop and sign in again.",
    unregistered: "Your device is no longer registered. Enroll it again.",
    suspended: "Your device is not approved (suspended). Ask your administrator.",
    pending: "Your device is not approved (pending approval). Ask your administrator.",
    noncompliant: "Your device does not meet the security requirements. Your administrator can see which checks failed.",
  };
  const denied = (message: string) => new UpstreamError(403, message, "APP_ACCESS_DENIED");

  it("recognises every device refusal", () => {
    expect(accessDenialReason(denied(gate.noDevice))).toBe("device_required");
    expect(accessDenialReason(denied(gate.unregistered))).toBe("device_unregistered");
    expect(accessDenialReason(denied(gate.suspended))).toBe("device_not_approved");
    expect(accessDenialReason(denied(gate.pending))).toBe("device_not_approved");
    expect(accessDenialReason(denied(gate.noncompliant))).toBe("device_noncompliant");
  });

  it("keeps the group message for a group refusal or anything it does not recognise", () => {
    expect(accessDenialReason(denied("your group does not have access to this app"))).toBe("app_access_denied");
    expect(accessDenialReason(denied(""))).toBe("app_access_denied");
    expect(accessDenialReason(null)).toBe("app_access_denied");
    expect(accessDenialReason("not an error")).toBe("app_access_denied");
  });

  it("every reason has wording, and none of it is the backend's text", () => {
    for (const [reason, text] of Object.entries(ACCESS_DENIAL_MESSAGES)) {
      expect(text.length, reason).toBeGreaterThan(20);
      expect(Object.values(gate)).not.toContain(text);
    }
    expect(ACCESS_DENIAL_MESSAGES.device_noncompliant).toContain("security checks");
  });

  it("only the fixed codes are accepted from a URL", () => {
    expect(isAccessDenialReason("device_noncompliant")).toBe(true);
    expect(isAccessDenialReason("app_access_denied")).toBe(true);
    expect(isAccessDenialReason("<script>")).toBe(false);
    expect(isAccessDenialReason("toString")).toBe(false);
    expect(isAccessDenialReason(undefined)).toBe(false);
  });
});
