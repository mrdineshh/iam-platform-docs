import { config } from "./config";
import { getJson } from "./http";

export interface Me {
  id: string;
  email: string | null;
  displayName: string | null;
  role: "ADMIN" | "USER";
}

/**
 * The signed-in person's own name and email, for the launchpad's account menu.
 * Purely cosmetic, so any failure returns null and the menu falls back to a
 * generic avatar rather than breaking the page.
 */
export async function getMe(sessionToken: string, correlationId: string): Promise<Me | null> {
  try {
    return await getJson<Me>(`${config.tenantSvcUrl}/api/v1/me`, {
      correlationId,
      timeoutMs: config.defaultTimeoutMs,
      headers: { "X-Session-Token": sessionToken },
    });
  } catch {
    return null;
  }
}
