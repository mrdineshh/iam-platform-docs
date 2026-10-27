// Pure helpers for the app launchpad (search, ordering, tile appearance).

export interface LaunchApp {
  id: string;
  name: string;
  launchUrl: string;
  type: "OIDC" | "SAML";
}

/** Alphabetical, then narrowed by a case-insensitive "contains" match on the name. */
export function filterApps<T extends { name: string }>(apps: T[], query: string): T[] {
  const q = query.trim().toLowerCase();
  const sorted = [...apps].sort((a, b) => a.name.localeCompare(b.name));
  return q ? sorted.filter((a) => a.name.toLowerCase().includes(q)) : sorted;
}

// Google-style product colors, used for the letter badge of apps with no logo of their own.
const PALETTE = ["#4285f4", "#ea4335", "#f9ab00", "#34a853", "#a142f4", "#12b5cb", "#e8710a", "#d93025"];

/** Stable per-name color: the same app always gets the same badge color. */
export function tileColor(name: string): string {
  let hash = 0;
  for (const ch of name) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
  return PALETTE[hash % PALETTE.length];
}

// Real logos for known apps, matched by name (case-insensitive).
const KNOWN_LOGOS: Array<{ match: string; src: string }> = [
  { match: "pulse", src: "/app-logos/pulse.svg" },
  { match: "google", src: "/app-logos/google.png" },
];

export function knownLogo(name: string): string | null {
  const lower = name.toLowerCase();
  return KNOWN_LOGOS.find((l) => lower.includes(l.match))?.src ?? null;
}
