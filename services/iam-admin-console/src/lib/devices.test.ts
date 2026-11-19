import { describe, expect, it } from "vitest";
import { agentOlderThan, BROWSER_CONTROLS_MIN_AGENT } from "./devices";

describe("agentOlderThan", () => {
  it("is true for any version before the minimum", () => {
    expect(agentOlderThan("0.3.4", "0.3.5")).toBe(true);
    expect(agentOlderThan("0.3.3", BROWSER_CONTROLS_MIN_AGENT)).toBe(true);
    expect(agentOlderThan("0.2.9", "0.3.5")).toBe(true);
  });

  it("is false for the minimum itself and anything newer", () => {
    expect(agentOlderThan("0.3.5", "0.3.5")).toBe(false);
    expect(agentOlderThan("0.3.6", "0.3.5")).toBe(false);
    expect(agentOlderThan("0.4.0", "0.3.5")).toBe(false);
    expect(agentOlderThan("1.0.0", "0.3.5")).toBe(false);
  });

  it("compares numbers, not text (0.3.10 is newer than 0.3.5)", () => {
    expect(agentOlderThan("0.3.10", "0.3.5")).toBe(false);
    expect(agentOlderThan("0.10.0", "0.9.9")).toBe(false);
  });

  it("treats an unknown or unreadable version as older, so the admin is warned rather than misled", () => {
    expect(agentOlderThan(null, "0.3.5")).toBe(true);
    expect(agentOlderThan(undefined, "0.3.5")).toBe(true);
    expect(agentOlderThan("", "0.3.5")).toBe(true);
    expect(agentOlderThan("unknown", "0.3.5")).toBe(true);
  });
});
