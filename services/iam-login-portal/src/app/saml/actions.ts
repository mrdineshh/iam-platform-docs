"use server";

import { cookies, headers } from "next/headers";
import { randomUUID } from "node:crypto";
import { config } from "@/lib/config";
import { login, type LoginResponse } from "@/lib/authClient";
import { completeSamlAuthorization } from "@/lib/samlClient";
import { denialMessage, isAppAccessDenied } from "@/lib/errorCodes";
import { UpstreamError } from "@/lib/http";
import { str } from "@/lib/formData";
import { resolveTenant } from "../login/actions";
import type { SamlLoginFormState } from "./types";

/**
 * SAML counterpart to loginAction -- identical authentication path (same
 * iam-auth-svc /login call, same SSO cookie), different completion: SAML's
 * HTTP-POST binding needs a real cross-origin form submit, which can't be
 * done via redirect() the way the OIDC flow's completeAuthorization is, so
 * this returns the acsUrl/samlResponse/relayState through form state for
 * SamlAutoPostForm to render and submit client-side instead.
 */
export async function samlLoginAction(_prevState: SamlLoginFormState, formData: FormData): Promise<SamlLoginFormState> {
  const correlationId = randomUUID();
  const requestHeaders = await headers();
  const sourceIp = requestHeaders.get("x-iam-internal-real-ip") ?? "";
  const userAgent = requestHeaders.get("user-agent") ?? undefined;

  const samlRequestId = str(formData.get("samlRequestId"));
  const tenantOverride = str(formData.get("tenantOverride")) || null;
  const email = str(formData.get("email")).trim();
  const password = str(formData.get("password"));
  const intent = str(formData.get("intent")) || "totp";
  const totpCode = str(formData.get("totpCode")).trim();

  if (!samlRequestId) {
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
        userAgent,
        totpCode: intent === "totp" ? totpCode : undefined,
      },
      correlationId,
    );
  } catch (err) {
    console.error("[samlLoginAction] login failed", err);
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

  if (!loginResult.token) {
    return { error: "Sign-in could not be completed. Please start again." };
  }

  (await cookies()).set(config.ssoCookieName, loginResult.token, {
    httpOnly: true,
    secure: config.ssoCookieSecure,
    sameSite: "lax",
    path: "/",
    maxAge: config.ssoCookieMaxAgeSeconds,
  });

  try {
    const completion = await completeSamlAuthorization({ sessionToken: loginResult.token, samlRequestId }, correlationId);
    return {
      autoPost: {
        acsUrl: completion.acsUrl,
        samlResponse: completion.samlResponse,
        relayState: completion.relayState,
      },
    };
  } catch (err) {
    if (isAppAccessDenied(err)) {
      return { error: denialMessage("APP_ACCESS_DENIED", ""), errorCode: "APP_ACCESS_DENIED" };
    }
    console.error("[samlLoginAction] saml/complete failed", err);
    // Never fail open: the session exists at this point, but if we can't
    // mint a signed assertion the caller must not be silently treated as
    // signed in to the third-party app.
    return { error: "Sign-in succeeded, but the request could not be completed. Please try again." };
  }
}
