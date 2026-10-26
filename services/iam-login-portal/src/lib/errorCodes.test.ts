import { describe, expect, it } from "vitest";
import { denialMessage, isPushError, isTotpError } from "./errorCodes";

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
