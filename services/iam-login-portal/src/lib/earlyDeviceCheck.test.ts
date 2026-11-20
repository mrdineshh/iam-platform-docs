import { describe, expect, it } from "vitest";
import { earlyDeviceNotice } from "./earlyDeviceCheck";

describe("earlyDeviceNotice", () => {
  it("says nothing when there is no answer or the tenant does not restrict sign-in by laptop", () => {
    expect(earlyDeviceNotice(null)).toBeNull();
    expect(earlyDeviceNotice(undefined)).toBeNull();
    expect(earlyDeviceNotice({ ruleOn: false, authorised: true })).toBeNull();
    // even a refusal is ignored when the rule is off: nothing may be shown for a tenant that does not use it
    expect(earlyDeviceNotice({ ruleOn: false, authorised: false, code: "DEVICE_REQUIRED" })).toBeNull();
  });

  it("says nothing for an authorised laptop", () => {
    expect(earlyDeviceNotice({ ruleOn: true, authorised: true })).toBeNull();
  });

  it("gives the specific reason for each refusal, starting with the same sentence as the real sign-in refusal", () => {
    for (const code of ["DEVICE_REQUIRED", "DEVICE_NOT_APPROVED", "DEVICE_NON_COMPLIANT"]) {
      expect(earlyDeviceNotice({ ruleOn: true, authorised: false, code }), code).toMatch(/^You are not authorised to sign in from this device/);
    }
    expect(earlyDeviceNotice({ ruleOn: true, authorised: false, code: "DEVICE_NON_COMPLIANT" })).toMatch(/security requirements/);
  });

  it("falls back to the generic refusal if the code is missing", () => {
    expect(earlyDeviceNotice({ ruleOn: true, authorised: false })).toMatch(/^You are not authorised to sign in from this device/);
  });
});
