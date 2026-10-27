import { describe, expect, it } from "vitest";
import { denialMessage, isAppAccessDenied, isPushError, isTotpError } from "./errorCodes";
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
