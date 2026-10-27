import { config } from "./config";
import { http } from "./http";

export interface Branding {
  primaryColor: string | null;
  logoUrl: string | null;
  headline: string | null;
  defaultTheme: "light" | "dark" | null;
}

export const EMPTY_BRANDING: Branding = { primaryColor: null, logoUrl: null, headline: null, defaultTheme: null };

const STORAGE_KEY = "iam-admin-console:branding";
const THEME_KEY = "iam-admin-console:theme";
const VARS = ["--iam-primary", "--iam-primary-hover", "--iam-primary-tint", "--iam-on-primary"];

function hexToRgb(hex: string): [number, number, number] {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function luminance([r, g, b]: [number, number, number]): number {
  const c = [r, g, b].map((v) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}

/** Derived tokens for a brand color: hover shade, soft tint, and a readable text color on top of it. */
export function deriveColorTokens(hex: string) {
  const rgb = hexToRgb(hex);
  const [r, g, b] = rgb;
  const darken = (v: number) => Math.round(v * 0.85);
  // Dark text on light brand colors, white on dark ones (WCAG relative luminance).
  const onPrimary = luminance(rgb) > 0.5 ? "#111827" : "#ffffff";
  return {
    "--iam-primary": hex,
    "--iam-primary-hover": `rgb(${darken(r)}, ${darken(g)}, ${darken(b)})`,
    "--iam-primary-tint": `rgba(${r}, ${g}, ${b}, 0.14)`,
    "--iam-on-primary": onPrimary,
  };
}

/**
 * Applies a tenant's branding to the whole page by overriding the --iam-*
 * custom properties on <html>. Pass null to go back to the default theme.
 * The last applied branding is remembered so every page (and a reload)
 * starts branded before the first paint of any data.
 */
export function applyBranding(branding: Branding | null | undefined): void {
  const root = document.documentElement;
  VARS.forEach((v) => root.style.removeProperty(v));

  if (!branding || (!branding.primaryColor && !branding.logoUrl && !branding.headline && !branding.defaultTheme)) {
    localStorage.removeItem(STORAGE_KEY);
    return;
  }

  if (branding.primaryColor && /^#[0-9a-fA-F]{6}$/.test(branding.primaryColor)) {
    Object.entries(deriveColorTokens(branding.primaryColor)).forEach(([k, v]) => root.style.setProperty(k, v));
  }

  // A person's own light/dark choice always wins; the tenant default only applies until they make one.
  if (branding.defaultTheme && !localStorage.getItem(THEME_KEY)) {
    root.setAttribute("data-theme", branding.defaultTheme);
  }

  localStorage.setItem(STORAGE_KEY, JSON.stringify(branding));
}

export function loadStoredBranding(): Branding | null {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Branding;
  } catch {
    return null;
  }
}

export function applyStoredBranding(): void {
  const stored = loadStoredBranding();
  if (stored) applyBranding(stored);
}

export function updateBranding(tenantId: string, branding: Branding, sessionToken: string): Promise<Branding> {
  return http.put<Branding>(
    `${config.tenantSvcUrl}/api/v1/admin/branding`,
    { tenantId, ...branding },
    { sessionToken },
  );
}
