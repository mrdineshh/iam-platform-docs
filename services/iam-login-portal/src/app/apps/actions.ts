"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { config } from "@/lib/config";

/**
 * Ends the platform session behind the SSO cookie and clears the cookie, then
 * sends the person back to the sign-in page. Ending the session is best-effort:
 * if the auth service is unreachable or the session is already gone, the cookie
 * is still cleared, so this browser is signed out either way.
 */
export async function signOutAction(tenantOverride: string | null): Promise<void> {
  const jar = await cookies();
  const token = jar.get(config.ssoCookieName)?.value;

  if (token) {
    try {
      await fetch(`${config.authSvcUrl}/api/v1/logout`, {
        method: "POST",
        headers: { "X-Session-Token": token },
        signal: AbortSignal.timeout(config.defaultTimeoutMs),
      });
    } catch {
      // Cookie is cleared below regardless.
    }
  }

  jar.delete(config.ssoCookieName);
  redirect(tenantOverride ? `/portal?tenant=${encodeURIComponent(tenantOverride)}` : "/portal");
}
