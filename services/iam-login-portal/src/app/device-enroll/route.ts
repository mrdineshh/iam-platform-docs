import { NextResponse, type NextRequest } from "next/server";
import { randomUUID } from "node:crypto";
import { config } from "@/lib/config";
import { UpstreamError } from "@/lib/http";
import {
  POST_LOGIN_NEXT_COOKIE,
  POST_LOGIN_NEXT_MAX_AGE_SECONDS,
  isValidKeyThumbprint,
  isValidState,
  loopbackCallbackUrl,
  parseLoopbackRedirectUri,
  startDeviceEnrollment,
} from "@/lib/deviceEnroll";

/**
 * Endpoint agent enrollment handoff -- the agent opens the system browser here with
 *   ?redirect_uri=http://127.0.0.1:<port>/callback&key_thumbprint=<S256 of its public key>&state=<random>
 * and gets redirected back to its own loopback listener with a single-use enrollment transaction
 * bound to that key (RFC 8252 loopback redirect + RFC 7636-style key binding). The browser's SSO
 * session token is only ever used server-side here; it never reaches the agent.
 *
 * Not signed in yet: the user is sent through the normal /portal login (password + second factor,
 * the one auth engine -- AP-1) and lands back here afterwards via the iam_post_login_next cookie.
 */
export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;
  const redirectUri = parseLoopbackRedirectUri(params.get("redirect_uri"));
  const keyThumbprint = params.get("key_thumbprint");
  const state = params.get("state");

  // An invalid redirect_uri is never redirected to, even to report the error -- that's what
  // prevents this endpoint being used as an open redirect.
  if (!redirectUri || !isValidKeyThumbprint(keyThumbprint) || !isValidState(state)) {
    return NextResponse.redirect(new URL("/login/error?reason=device_enroll_invalid", request.url));
  }

  const sessionToken = request.cookies.get(config.ssoCookieName)?.value;
  if (!sessionToken) {
    return redirectToLogin(request);
  }

  try {
    const authorization = await startDeviceEnrollment(sessionToken, keyThumbprint, randomUUID());
    return toAgent(
      loopbackCallbackUrl(redirectUri, {
        enrollment_transaction_id: authorization.enrollmentTransactionId,
        nonce: authorization.nonce,
        state,
      }),
    );
  } catch (err) {
    if (err instanceof UpstreamError && err.status === 401) {
      // The SSO cookie outlived its session -- sign in again rather than failing.
      const response = redirectToLogin(request);
      response.cookies.delete(config.ssoCookieName);
      return response;
    }
    console.error("[device-enroll] enrollment/start failed", err);
    // redirect_uri has been validated as loopback above, so reporting the failure to the agent
    // (RFC 6749 Section 4.1.2.1 style) is safe -- it lets the agent stop waiting instead of hanging.
    return toAgent(loopbackCallbackUrl(redirectUri, { error: "temporarily_unavailable", state }));
  }
}

function redirectToLogin(request: NextRequest): NextResponse {
  const tenantOverride = request.nextUrl.searchParams.get("tenant");
  const portal = new URL("/portal", request.url);
  if (tenantOverride) portal.searchParams.set("tenant", tenantOverride);

  const response = NextResponse.redirect(portal);
  response.cookies.set(POST_LOGIN_NEXT_COOKIE, `${request.nextUrl.pathname}${request.nextUrl.search}`, {
    httpOnly: true,
    secure: config.ssoCookieSecure,
    sameSite: "lax",
    path: "/",
    maxAge: POST_LOGIN_NEXT_MAX_AGE_SECONDS,
  });
  return response;
}

function toAgent(url: string): NextResponse {
  const response = NextResponse.redirect(url, 302);
  // The enrollment transaction is a one-time credential in the URL -- never cache it, and never
  // leak it via Referer to whatever the agent's success page might load.
  response.headers.set("Cache-Control", "no-store");
  response.headers.set("Referrer-Policy", "no-referrer");
  response.cookies.delete(POST_LOGIN_NEXT_COOKIE);
  return response;
}
