interface SearchParams {
  reason?: string;
}

const MESSAGES: Record<string, string> = {
  missing_params: "This sign-in link is missing required information.",
  tenant_unresolved: "Could not determine which organization to sign in to.",
  tenant_not_found: "No organization was found for this sign-in link.",
  unavailable: "Sign-in is temporarily unavailable. Please try again shortly.",
};

// Defense in depth (docs/specs/iam-login-portal-SPEC.md Section 4):
// iam-oidcprovider-svc already validates client_id/redirect_uri before
// ever redirecting here, but a malformed or hand-crafted URL must still
// render a friendly page, not crash the portal.
export default async function LoginErrorPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const { reason } = await searchParams;
  const message = (reason && MESSAGES[reason]) || "Sign-in request could not be processed.";

  return (
    <main className="login-page">
      <p className="login-form__error">{message}</p>
    </main>
  );
}
