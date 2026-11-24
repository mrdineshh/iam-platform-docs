import { describe, expect, it } from "vitest";
import { generatePassword } from "./generatePassword";

describe("generatePassword", () => {
  it("is the requested length and has an uppercase letter, a lowercase letter, a digit and a symbol", () => {
    for (let i = 0; i < 50; i++) {
      const p = generatePassword();
      expect(p).toHaveLength(14);
      expect(p).toMatch(/[A-Z]/);
      expect(p).toMatch(/[a-z]/);
      expect(p).toMatch(/[0-9]/);
      expect(p).toMatch(/[!@#$%&*?]/);
    }
  });

  it("never uses look-alike characters", () => {
    for (let i = 0; i < 50; i++) expect(generatePassword(40)).not.toMatch(/[0OIl1]/);
  });

  it("differs between calls", () => {
    expect(generatePassword()).not.toBe(generatePassword());
  });
});
