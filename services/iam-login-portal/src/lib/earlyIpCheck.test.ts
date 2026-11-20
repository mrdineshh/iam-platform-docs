import { describe, expect, it } from "vitest";
import { earlyIpNotice } from "./earlyIpCheck";

describe("earlyIpNotice", () => {
  it("says nothing when there is no answer or the address is allowed", () => {
    expect(earlyIpNotice(null)).toBeNull();
    expect(earlyIpNotice(undefined)).toBeNull();
    expect(earlyIpNotice({ allowed: true })).toBeNull();
  });

  it("uses the same wording as the refusal after the password", () => {
    expect(earlyIpNotice({ allowed: false, errorCode: "POLICY_DENIED" })).toBe("Sign-in isn't allowed from your current location or network.");
    expect(earlyIpNotice({ allowed: false, errorCode: "LOCATION_UNVERIFIED" })).toMatch(/verify your location/);
    expect(earlyIpNotice({ allowed: false, errorCode: "POLICY_UNAVAILABLE" })).toMatch(/could not be evaluated/);
  });

  it("falls back to the plain refusal if the code is missing or unknown", () => {
    expect(earlyIpNotice({ allowed: false })).toBe("Sign-in isn't allowed from your current location or network.");
    expect(earlyIpNotice({ allowed: false, errorCode: "SOMETHING_NEW" })).toBe("Sign-in isn't allowed from your current location or network.");
  });

  it("never shows the server's raw reason text", () => {
    expect(earlyIpNotice({ allowed: false, errorCode: "POLICY_DENIED", reason: "source IP is not in allowedCidrs" })).not.toMatch(/allowedCidrs/);
  });
});
