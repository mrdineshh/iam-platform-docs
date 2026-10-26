import { describe, expect, it } from "vitest";
import { resolveTenantSubdomain } from "./tenant";

describe("resolveTenantSubdomain", () => {
  it("extracts the subdomain from a real Host header under the platform root domain", () => {
    expect(resolveTenantSubdomain("acme.platform.example.com:3000", null)).toBe("acme");
  });

  it("falls back to the dev override when the Host header has no recognizable subdomain", () => {
    expect(resolveTenantSubdomain("localhost:3000", "acme")).toBe("acme");
  });

  it("prefers the real subdomain over the dev override when both are present", () => {
    expect(resolveTenantSubdomain("acme.platform.example.com:3000", "someone-else")).toBe("acme");
  });

  it("returns null when neither a real subdomain nor an override is available", () => {
    expect(resolveTenantSubdomain("localhost:3000", null)).toBeNull();
  });

  it("returns null for a null Host header and no override", () => {
    expect(resolveTenantSubdomain(null, null)).toBeNull();
  });

  it("never matches the bare root domain itself as a subdomain", () => {
    expect(resolveTenantSubdomain("platform.example.com:3000", null)).toBeNull();
  });
});
