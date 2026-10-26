import { config } from "./config";

/**
 * This SPA has no server of its own, so the only way it can learn its own
 * real public IP is to ask something that CAN see it -- nginx's /whoami
 * endpoint, which reflects back whatever Caddy (the host-level reverse
 * proxy in front) observed the connection as. Falls back to the old fixed
 * dev-only value if that endpoint is unreachable or empty (e.g. a local
 * run with no Caddy in front at all).
 */
export async function detectRealIp(): Promise<string> {
  try {
    const res = await fetch("/whoami", { cache: "no-store" });
    if (!res.ok) return config.devOnlySourceIp;
    const body = (await res.json()) as { ip?: string };
    if (!body.ip) return config.devOnlySourceIp;
    // Caddy appends (not replaces) X-Forwarded-For, so if a client sent
    // their own fake value this is "fake, real" -- the last entry is
    // always the one Caddy itself observed.
    const hops = body.ip.split(",").map((ip) => ip.trim());
    return hops[hops.length - 1] || config.devOnlySourceIp;
  } catch {
    return config.devOnlySourceIp;
  }
}
