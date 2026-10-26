import { NextResponse, type NextRequest } from "next/server";
import { config } from "@/lib/config";

/**
 * Lets iam-admin-console's own "My Apps" launchpad hand off its session
 * into the SSO cookie this service owns -- admin-console is a pure
 * browser SPA with no server of its own, so it can never set the httpOnly
 * cookie /login/page.tsx checks on every /authorize visit. Without this,
 * a user who signed in via admin-console (rather than this service's own
 * /portal) would always be re-prompted the first time they open an app,
 * even though their platform session is perfectly valid.
 *
 * POST-only, deliberately: a bare GET link could be clicked/prefetched
 * from anywhere, but a form POST only fires from code that already holds
 * the token (admin-console's own page) -- not something a stray link or
 * browser prefetch can trigger. The token itself grants nothing on its
 * own here; whatever app this redirects into still re-validates the
 * session via /authorize/complete before trusting it (AP-3).
 */
export async function POST(request: NextRequest) {
  const formData = await request.formData();
  const token = String(formData.get("token") ?? "");
  const next = String(formData.get("next") ?? "");

  if (!token || !next.startsWith("https://")) {
    return NextResponse.redirect(new URL("/login/error?reason=missing_params", request.url));
  }

  // 303, not the default 307 -- a 307/308 preserves the original method, so
  // the browser would re-issue this as a POST against `next` too. Pulse's
  // (and any app's) own oidc/start endpoint is GET-only, hence the earlier
  // "Cannot POST /api/v1/auth/oidc/start" -- 303 is the standard fix for
  // the Post/Redirect/Get pattern, forcing the next hop to GET regardless.
  const response = NextResponse.redirect(next, 303);
  response.cookies.set(config.ssoCookieName, token, {
    httpOnly: true,
    secure: config.ssoCookieSecure,
    sameSite: "lax",
    path: "/",
    maxAge: config.ssoCookieMaxAgeSeconds,
  });
  return response;
}
