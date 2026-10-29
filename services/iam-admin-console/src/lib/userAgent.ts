/** Turns a User-Agent string into something a person can read, e.g. "Chrome on Windows". */
export function describeUserAgent(ua: string | null | undefined): string {
  if (!ua) return "Unknown device";
  const browser =
    /Edg(e|A|iOS)?\//.test(ua) ? "Edge"
    : /OPR\/|Opera/.test(ua) ? "Opera"
    : /Firefox\/|FxiOS/.test(ua) ? "Firefox"
    : /Chrome\/|CriOS/.test(ua) ? "Chrome"
    : /Safari\//.test(ua) ? "Safari"
    : /curl\//i.test(ua) ? "curl"
    : null;
  const os =
    /Windows NT/.test(ua) ? "Windows"
    : /Android/.test(ua) ? "Android"
    : /iPhone|iPad|iPod/.test(ua) ? "iOS"
    : /Mac OS X|Macintosh/.test(ua) ? "macOS"
    : /CrOS/.test(ua) ? "ChromeOS"
    : /Linux/.test(ua) ? "Linux"
    : null;
  if (browser && os) return `${browser} on ${os}`;
  return browser ?? os ?? "Unknown device";
}

const countryNames = typeof Intl !== "undefined" && "DisplayNames" in Intl ? new Intl.DisplayNames(["en"], { type: "region" }) : null;

/** "Chennai, Tamil Nadu, India" from the parts a session carries; null when none were recorded. */
export function describeLocation(city?: string | null, region?: string | null, country?: string | null): string | null {
  let countryName = country ?? null;
  if (country && countryNames) {
    try {
      countryName = countryNames.of(country) ?? country;
    } catch {
      countryName = country;
    }
  }
  const parts = [city, region, countryName].filter((p): p is string => !!p && p.trim() !== "");
  // Some databases repeat the city as the region ("Singapore, Singapore"); show it once.
  const unique = parts.filter((p, i) => parts.indexOf(p) === i);
  return unique.length ? unique.join(", ") : null;
}
