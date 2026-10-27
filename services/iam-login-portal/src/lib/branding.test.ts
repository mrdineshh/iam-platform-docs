import { describe, expect, it } from "vitest";
import { brandStyle, safeLogoUrl } from "./branding";

const base = { primaryColor: null, logoUrl: null, headline: null, defaultTheme: null };

describe("brandStyle", () => {
  it("returns nothing for a tenant with no branding", () => {
    expect(brandStyle(null)).toBeUndefined();
    expect(brandStyle(base)).toBeUndefined();
  });

  it("derives the hover, tint and text tokens from the brand color", () => {
    const style = brandStyle({ ...base, primaryColor: "#336699" }) as Record<string, string>;
    expect(style["--iam-primary"]).toBe("#336699");
    expect(style["--iam-primary-hover"]).toBe("rgb(43, 87, 130)");
    expect(style["--iam-primary-tint"]).toBe("rgba(51, 102, 153, 0.14)");
    expect(style["--iam-on-primary"]).toBe("#ffffff");
  });

  it("uses dark text on a light brand color so buttons stay readable", () => {
    const style = brandStyle({ ...base, primaryColor: "#ffe066" }) as Record<string, string>;
    expect(style["--iam-on-primary"]).toBe("#111827");
  });

  it("refuses anything that is not a strict #RRGGBB value (CSS-injection guard)", () => {
    expect(brandStyle({ ...base, primaryColor: "red; background:url(x)" })).toBeUndefined();
    expect(brandStyle({ ...base, primaryColor: "#fff" })).toBeUndefined();
    expect(brandStyle({ ...base, primaryColor: "#12345g" })).toBeUndefined();
  });
});

describe("safeLogoUrl", () => {
  it("accepts https URLs only", () => {
    expect(safeLogoUrl({ ...base, logoUrl: "https://cdn.example.com/logo.png" })).toBe("https://cdn.example.com/logo.png");
    expect(safeLogoUrl({ ...base, logoUrl: "http://cdn.example.com/logo.png" })).toBeNull();
    expect(safeLogoUrl({ ...base, logoUrl: "javascript:alert(1)" })).toBeNull();
    expect(safeLogoUrl({ ...base, logoUrl: "data:image/png;base64,AAAA" })).toBeNull();
    expect(safeLogoUrl(null)).toBeNull();
  });
});
