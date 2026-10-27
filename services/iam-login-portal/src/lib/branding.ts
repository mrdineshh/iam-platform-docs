import type { CSSProperties } from "react";

/**
 * Per-tenant branding (FR-6.1) as returned, publicly, by iam-tenant-svc's
 * tenant lookup. Every value is validated server-side (#RRGGBB color, https
 * logo), and brandStyle() re-checks the color anyway -- it ends up inside a
 * CSS custom property, so only a strict hex value is ever allowed through.
 */
export interface Branding {
  primaryColor: string | null;
  logoUrl: string | null;
  headline: string | null;
  defaultTheme: "light" | "dark" | null;
}

const HEX = /^#[0-9a-fA-F]{6}$/;

function luminance(r: number, g: number, b: number): number {
  const lin = [r, g, b].map((v) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2];
}

export function brandStyle(branding: Branding | null | undefined): CSSProperties | undefined {
  const color = branding?.primaryColor;
  if (!color || !HEX.test(color)) return undefined;

  const n = parseInt(color.slice(1), 16);
  const r = (n >> 16) & 255;
  const g = (n >> 8) & 255;
  const b = n & 255;
  const darken = (v: number) => Math.round(v * 0.85);

  return {
    "--iam-primary": color,
    "--iam-primary-hover": `rgb(${darken(r)}, ${darken(g)}, ${darken(b)})`,
    "--iam-primary-tint": `rgba(${r}, ${g}, ${b}, 0.14)`,
    "--iam-on-primary": luminance(r, g, b) > 0.5 ? "#111827" : "#ffffff",
  } as CSSProperties;
}

export function safeLogoUrl(branding: Branding | null | undefined): string | null {
  const url = branding?.logoUrl;
  return url && /^https:\/\/\S+$/.test(url) ? url : null;
}
