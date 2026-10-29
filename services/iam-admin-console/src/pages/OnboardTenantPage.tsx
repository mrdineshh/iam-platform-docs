import { useState } from "react";

import { createTenant, type Tenant } from "@/lib/tenant";
import { UpstreamError } from "@/lib/http";
import { ThemeToggle } from "@/components/ThemeToggle";
import { BackLink } from "@/components/ui";

/**
 * Public (no session) tenant self-onboarding -- there's no session to hold
 * yet at this point (this is how the very first tenant comes to exist),
 * same reasoning as LoginPage needing no auth to render. Mirrors
 * POST /api/v1/tenants exactly (contracts/iam-tenant-svc.yaml), which is
 * deliberately unauthenticated server-side already -- this page doesn't
 * change that security posture, just gives it a UI instead of curl.
 *
 * Only creates the Tenant row. The first admin user still has to be
 * created against iam-identity-svc directly (mTLS-only inbound -- no
 * browser SPA can call it), so that step isn't in scope here.
 */
export function OnboardTenantPage() {
  const [name, setName] = useState("");
  const [subdomain, setSubdomain] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [created, setCreated] = useState<Tenant | null>(null);

  const subdomainPattern = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

  async function submit() {
    setError(null);
    if (!name.trim()) {
      setError("Enter an organization name.");
      return;
    }
    if (!subdomainPattern.test(subdomain)) {
      setError("Subdomain must be lowercase letters, numbers, and hyphens only.");
      return;
    }

    setPending(true);
    try {
      const tenant = await createTenant(name.trim(), subdomain);
      setCreated(tenant);
    } catch (err) {
      if (err instanceof UpstreamError && err.status === 409) {
        setError("That subdomain is already taken.");
      } else if (err instanceof UpstreamError && err.status === 400) {
        setError(err.message);
      } else {
        setError("Onboarding is temporarily unavailable. Please try again.");
      }
    } finally {
      setPending(false);
    }
  }

  if (created) {
    return (
      <main className="login-page">
        <ThemeToggle className="login-page__theme-toggle" />
        <div className="login-form">
          <h1>Tenant created</h1>
          <p>
            <strong>{created.name}</strong> is now onboarded on subdomain <code>{created.subdomain}</code>.
          </p>
          <p>
            Tenant ID: <code>{created.id}</code>
          </p>
          <p>
            Next: the first admin user for this tenant still has to be created against iam-identity-svc directly
            (it requires mTLS, so no browser page can do it yet) — use the same API call as any other user
            enrollment for now.
          </p>
          <BackLink to="/login">Back to sign in</BackLink>
        </div>
      </main>
    );
  }

  return (
    <main className="login-page">
      <ThemeToggle className="login-page__theme-toggle" />
      <form
        className="login-form"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <h1>Onboard a new organization</h1>

        {error && (
          <p role="alert" className="login-form__error">
            {error}
          </p>
        )}

        <label className="login-form__field">
          Organization name
          <input type="text" value={name} onChange={(e) => setName(e.target.value)} required placeholder="Acme Inc." />
        </label>

        <label className="login-form__field">
          Subdomain
          <input
            type="text"
            value={subdomain}
            onChange={(e) => setSubdomain(e.target.value.toLowerCase())}
            required
            placeholder="acme"
            pattern="[a-z0-9-]+"
          />
        </label>

        <div className="login-form__buttons">
          <button type="submit" disabled={pending}>
            {pending ? "Creating…" : "Create tenant"}
          </button>
        </div>

        <p>
          <BackLink to="/login">Back to sign in</BackLink>
        </p>
      </form>
    </main>
  );
}
