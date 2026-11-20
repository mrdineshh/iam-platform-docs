import { describe, expect, it } from "vitest";
import { enterAction, type LoginStep } from "./loginSteps";

describe("enterAction", () => {
  it("makes Enter act like Next on the username screen", () => {
    expect(enterAction("username")).toBe("advance-username");
  });

  it("makes Enter act like Next on the password screen", () => {
    expect(enterAction("password")).toBe("advance-password");
  });

  it("leaves Enter to the form's own submit button on every other screen", () => {
    const others: LoginStep[] = ["enroll", "code", "submitting-no-code"];
    for (const step of others) expect(enterAction(step), step).toBe("submit");
  });
});
