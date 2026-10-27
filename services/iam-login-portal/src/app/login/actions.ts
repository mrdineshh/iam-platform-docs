"use server";

import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { randomUUID } from "node:crypto";
import { config } from "@/lib/config";
import { login, precheck, type LoginResponse } from "@/lib/authClient";
import { completeAuthorization } from "@/lib/oidcClient";
import { denialMessage, isAppAccessDenied } from "@/lib/errorCodes";
import { UpstreamError } from "@/lib/http";
import { findTenantBySubdomain, resolveTenantSubdomain, type Tenant } from "@/lib/tenant";
import { str } from "@/lib/formData";
import type { LoginFormState, PrecheckActionInput, PrecheckActionResult } from "./types";

/** Shared by loginAction, precheckAction, and saml/actions.ts -- resolves which tenant this subdomain belongs to. */
export async function resolveTenant(tenantOverride: string | null, correlationId: string): Promise<Tenant | { error: string }> {
  const host = (await headers()).get("host");
  const subdomain = resolveTenantSubdomain(host, tenantOverride);
  if (!subdomain) {
    return { error: "Could not determine which organization to sign in to." };
  }
  try {
    const tenant = await findTenantBySubdomain(subdomain, correlationId);
    if (!tenant) {
      return { error: "No organization was found for this sign-in link." };
    }
    return tenant;
  } catch (err) {
    console.error("[resolveTenant] tenant lookup failed", err);
    return { error: "Sign-in is temporarily unavailable. Please try again." };
  }
}

/**
 * Called directly (not via a <form action>) from the password step, before
 * the code screen ever renders -- finds out whether a code is needed at all
 * (mfaRequired=false lets the wizard skip straight to signing in) and, if
 * so, whether this is a first-time device enrollment (so the wizard can
 * show the QR). Deliberately never calls /login's push path -- see
 * authClient.precheck.
 */
export async function precheckAction(input: PrecheckActionInput): Promise<PrecheckActionResult> {
  const correlationId = randomUUID();
  const requestHeaders = await headers();
  const sourceIp = requestHeaders.get("x-iam-internal-real-ip") ?? "";

  const tenant = await resolveTenant(input.tenantOverride, correlationId);
  if ("error" in tenant) {
    return { ok: false, error: tenant.error };
  }

  try {
    const result = await precheck(
      { tenantId: tenant.id, email: input.email, password: input.password, sourceIp },
      correlationId,
    );
    if (!result.mfaRequired) {
      return { ok: true, mfaRequired: false };
    }
    if (result.enrollmentRequired) {
      return {
        ok: true,
        mfaRequired: true,
        enrollmentRequired: true,
        totpSecret: result.totpSecret,
        provisioningUri: result.provisioningUri,
      };
    }
    return { ok: true, mfaRequired: true, enrollmentRequired: false };
  } catch (err) {
    console.error("[precheckAction] precheck failed", err);
    if (err instanceof UpstreamError) {
      if (err.status === 401) {
        return { ok: false, error: "Incorrect email or password." };
      }
      if (err.status === 403) {
        return { ok: false, error: denialMessage(err.errorCode, err.message), errorCode: err.errorCode };
      }
    }
    return { ok: false, error: "Sign-in is temporarily unavailable. Please try again." };
  }
}

/**
 * The single form-submission handler for both the TOTP path and the push
 * path (docs/specs/iam-login-portal-SPEC.md Section 2) -- iam-auth-svc has
 * one /login endpoint that takes password + an optional totpCode in the
 * same call, so there's no separate "check password first" step; which
 * button was clicked (`intent`) only decides whether totpCode is forwarded
 * or dropped, not two different backend calls.
 */
export async function loginAction(_prevState: LoginFormState, formData: FormData): Promise<LoginFormState> {
  const correlationId = randomUUID();
  const requestHeaders = await headers();
  // Never a client-supplied field -- overwritten unconditionally by
  // server.js off the raw TCP socket before Next ever sees the request.
  const sourceIp = requestHeaders.get("x-iam-internal-real-ip") ?? "";

  const clientId = str(formData.get("clientId"));
  const redirectUri = str(formData.get("redirectUri"));
  const scope = str(formData.get("scope")) || "openid";
  const state = str(formData.get("state"));
  const tenantOverride = str(formData.get("tenantOverride")) || null;
  const email = str(formData.get("email")).trim();
  const password = str(formData.get("password"));
  const intent = str(formData.get("intent")) || "totp";
  const totpCode = str(formData.get("totpCode")).trim();

  // /portal submits with all three blank (no specific app requested yet --
  // see portal/page.tsx); /login always supplies all three together. A
  // request with only some of them set is malformed either way.
  const portalMode = !clientId && !redirectUri && !state;
  if (!portalMode && (!clientId || !redirectUri || !state)) {
    return { error: "This sign-in request is missing required information. Please restart from the application you were signing in to." };
  }
  if (!email || !password) {
    return { error: "Enter your email and password." };
  }
  if (intent === "totp" && !/^\d{6}$/.test(totpCode)) {
    return { error: "Enter the 6-digit code from your authenticator app." };
  }

  const tenant = await resolveTenant(tenantOverride, correlationId);
  if ("error" in tenant) {
    return { error: tenant.error };
  }

  let loginResult: LoginResponse;
  try {
    loginResult = await login(
      {
        tenantId: tenant.id,
        email,
        password,
        sourceIp,
        totpCode: intent === "totp" ? totpCode : undefined,
      },
      correlationId,
    );
  } catch (err) {
    console.error("[loginAction] login failed", err);
    if (err instanceof UpstreamError) {
      if (err.status === 401) {
        return { error: "Incorrect email or password." };
      }
      if (err.status === 403) {
        return { error: denialMessage(err.errorCode, err.message), errorCode: err.errorCode };
      }
    }
    return { error: "Sign-in is temporarily unavailable. Please try again." };
  }

  // A device change between the precheck and this submit (e.g. enrollment
  // offered elsewhere in the meantime) could in theory return
  // enrollmentRequired here instead of a token -- never fail open by
  // treating that as signed-in.
  if (!loginResult.token) {
    return { error: "Sign-in could not be completed. Please start again." };
  }

  // Single sign-on: remember this session in the browser so the *next*
  // app's /authorize redirect can reuse it without prompting again (see
  // page.tsx). Must be set before redirect() below -- redirect() signals
  // by throwing, so nothing after it ever runs.
  (await cookies()).set(config.ssoCookieName, loginResult.token, {
    httpOnly: true,
    secure: config.ssoCookieSecure,
    sameSite: "lax",
    path: "/",
    maxAge: config.ssoCookieMaxAgeSeconds,
  });

  if (portalMode) {
    redirect(tenantOverride ? `/apps?tenant=${encodeURIComponent(tenantOverride)}` : "/apps");
  }

  let redirectTarget: string;
  try {
    const completion = await completeAuthorization(
      { sessionToken: loginResult.token, clientId, redirectUri, scope, state },
      correlationId,
    );
    redirectTarget = completion.redirectUri;
  } catch (err) {
    if (isAppAccessDenied(err)) {
      return { error: denialMessage("APP_ACCESS_DENIED", ""), errorCode: "APP_ACCESS_DENIED" };
    }
    console.error("[loginAction] authorize/complete failed", err);
    // Never fail open: the session exists at this point, but if we can't
    // mint an OIDC code the caller must not be silently treated as signed
    // in to the third-party app.
    return { error: "Sign-in succeeded, but the request could not be completed. Please try again." };
  }

  redirect(redirectTarget);
}
