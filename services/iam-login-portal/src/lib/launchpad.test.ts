import { describe, expect, it } from "vitest";
import { accountInitial, filterApps, knownLogo, tileColor } from "./launchpad";

const apps = [
  { id: "1", name: "Pulse" },
  { id: "2", name: "google Workspace" },
  { id: "3", name: "Jira" },
];

describe("filterApps", () => {
  it("lists apps alphabetically when there is no query", () => {
    expect(filterApps(apps, "").map((a) => a.name)).toEqual(["google Workspace", "Jira", "Pulse"]);
  });

  it("matches anywhere in the name, ignoring case and surrounding spaces", () => {
    expect(filterApps(apps, "  WORK ").map((a) => a.id)).toEqual(["2"]);
    expect(filterApps(apps, "ul").map((a) => a.id)).toEqual(["1"]);
  });

  it("returns nothing when no app matches, and does not mutate the input", () => {
    const copy = [...apps];
    expect(filterApps(apps, "zzz")).toEqual([]);
    expect(apps).toEqual(copy);
  });
});

describe("tileColor", () => {
  it("is stable for the same name and always one of the palette colors", () => {
    expect(tileColor("Jira")).toBe(tileColor("Jira"));
    expect(tileColor("Jira")).toMatch(/^#[0-9a-f]{6}$/);
  });
});

describe("accountInitial", () => {
  it("uses the name first, then the email, then the fallback", () => {
    expect(accountInitial("ada lovelace", "x@y.z")).toBe("A");
    expect(accountInitial("  ", "bob@econz.net")).toBe("B");
    expect(accountInitial(null, null)).toBe("?");
    expect(accountInitial(null, null, "E")).toBe("E");
  });
});

describe("knownLogo", () => {
  it("finds logos for known apps by name, case-insensitively", () => {
    expect(knownLogo("Google Workspace")).toBe("/app-logos/google.png");
    expect(knownLogo("PULSE")).toBe("/app-logos/pulse.svg");
  });

  it("returns null for apps without a logo", () => {
    expect(knownLogo("Jira")).toBeNull();
  });
});
