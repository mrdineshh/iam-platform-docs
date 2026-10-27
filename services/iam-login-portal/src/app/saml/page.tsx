import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { randomUUID } from "node:crypto";
import { SamlLoginForm } from "./SamlLoginForm";
import { SplitShell } from "../SplitShell";
import { SamlAutoPostForm } from "./SamlAutoPostForm";
import { config } from "@/lib/config";
import { completeSamlAuthorization } from "@/lib/samlClient";
import { findTenantBySubdomain, resolveTenantSubdomain } from "@/lib/tenant";
import { brandStyle, safeLogoUrl } from "@/lib/branding";

interface SearchParams {
  saml_request_id?: string;
  tenant?: string;
}

// Reached via iam-oidcprovider-svc's GET /saml/sso redirect (SP-initiated
// SSO) -- saml_request_id is the opaque ID that endpoint stored the parsed
// AuthnRequest under, not the raw SAML XML itself.
export default async function SamlLoginPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await searchParams;
  const requestHeaders = await headers();

  const samlRequestId = params.saml_request_id ?? "";
  const tenantOverride = params.tenant ?? null;

  if (!samlRequestId) {
    redirect("/login/error?reason=missing_params");
  }

  const correlationId = randomUUID();

  // Single sign-on: if this browser already holds a live platform session
  // (signed in earlier via /portal or another app), complete the SAML
  // assertion straight away instead of showing the form -- same shortcut
  // /login/page.tsx has for the OIDC flow, just rendering an auto-post
  // form instead of doing a server-side redirect (HTTP-POST binding has
  // no redirect equivalent).
  const ssoToken = (await cookies()).get(config.ssoCookieName)?.value;
  if (ssoToken) {
    try {
      const completion = await completeSamlAuthorization({ sessionToken: ssoToken, samlRequestId }, correlationId);
      return (
        <main className="login-page">
          <SamlAutoPostForm acsUrl={completion.acsUrl} samlResponse={completion.samlResponse} relayState={completion.relayState} />
        </main>
      );
    } catch {
      // Falls through to the normal login form below -- an expired,
      // terminated, or foreign session fails closed, not silently.
    }
  }

  const subdomain = resolveTenantSubdomain(requestHeaders.get("host"), tenantOverride);
  if (!subdomain) {
    redirect("/login/error?reason=tenant_unresolved");
  }

  let tenant;
  try {
    tenant = await findTenantBySubdomain(subdomain, correlationId);
  } catch {
    redirect("/login/error?reason=unavailable");
  }
  if (!tenant) {
    redirect("/login/error?reason=tenant_not_found");
  }

  return (
    <SplitShell style={brandStyle(tenant.branding)}>
      <SamlLoginForm
        samlRequestId={samlRequestId}
        tenantOverride={tenantOverride}
        tenantName={tenant.name}
        logoUrl={safeLogoUrl(tenant.branding)}
        headline={tenant.branding?.headline}
      />
    </SplitShell>
  );
}
