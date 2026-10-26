import { describe, expect, it } from "vitest";
import { resolveTenantSubdomain } from "./tenant";

describe("resolveTenantSubdomain", () => {
  it("extracts the subdomain from a real hostname under the platform root domain", () => {
    expect(resolveTenantSubdomain("acme.platform.example.com", null)).toBe("acme");
  });

  it("falls back to the dev override when the hostname has no recognizable subdomain", () => {
    expect(resolveTenantSubdomain("localhost", "acme")).toBe("acme");
  });

  it("prefers the real subdomain over the dev override when both are present", () => {
    expect(resolveTenantSubdomain("acme.platform.example.com", "someone-else")).toBe("acme");
  });

  it("returns null when neither a real subdomain nor an override is available", () => {
    expect(resolveTenantSubdomain("localhost", null)).toBeNull();
  });

  it("never matches the bare root domain itself as a subdomain", () => {
    expect(resolveTenantSubdomain("platform.example.com", null)).toBeNull();
  });
});
