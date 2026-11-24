import { describe, expect, it } from "vitest";
import { userSignInLink } from "./signInLink";

describe("userSignInLink", () => {
  it("points at the login portal's sign-in page for the organization", () => {
    expect(userSignInLink("https://login.example.com", "grtjewels")).toBe("https://login.example.com/login?tenant=grtjewels");
  });

  it("ignores a trailing slash on the portal address", () => {
    expect(userSignInLink("https://login.example.com/", "acme")).toBe("https://login.example.com/login?tenant=acme");
  });

  it("falls back to the plain sign-in page when the organization is unknown", () => {
    expect(userSignInLink("https://login.example.com", null)).toBe("https://login.example.com/login");
  });
});
