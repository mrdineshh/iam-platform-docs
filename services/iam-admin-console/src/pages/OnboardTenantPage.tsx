import { useState } from "react";

import { createTenant, type Tenant } from "@/lib/tenant";
import { UpstreamError } from "@/lib/http";
import { loadSession } from "@/lib/session";
import { Alert, PageHeader, PendingLabel } from "@/components/ui";

/**
 * Platform-operator tenant onboarding. Only an administrator of the operator's own organization (econz) can use it:
 * the server checks the signed-in session on POST /api/v1/tenants, and the sidebar link only appears for them
 * (GET /api/v1/tenants/can-onboard). Anyone else, signed in or not, is refused.
 *
 * Only creates the Tenant row. The first admin user still has to be created against iam-identity-svc directly
 * (mTLS-only inbound -- no browser SPA can call it), so that step isn't in scope here.
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
    const session = loadSession();
    if (!session) return;
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
      setCreated(await createTenant(name.trim(), subdomain, session.token));
    } catch (err) {
      if (err instanceof UpstreamError && err.status === 403) {
        setError("Only the platform operator's administrators can onboard an organization.");
      } else if (err instanceof UpstreamError && err.status === 409) {
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
      <main className="page">
        <PageHeader title="Organization created" subtitle={`${created.name} is now onboarded.`} />
        <div className="card card--padded">
          <p>
            Subdomain: <code>{created.subdomain}</code>
          </p>
          <p>
            Tenant ID: <code>{created.id}</code>
          </p>
          <p className="hint">
            Next: the first admin user for this organization still has to be created against iam-identity-svc directly (it
            requires mTLS, so no browser page can do it yet).
          </p>
          <button
            type="button"
            onClick={() => {
              setCreated(null);
              setName("");
              setSubdomain("");
            }}
          >
            Onboard another
          </button>
        </div>
      </main>
    );
  }

  return (
    <main className="page">
      <PageHeader title="Onboard an organization" subtitle="Create a new organization on the platform." />

      {error && <Alert kind="error">{error}</Alert>}

      <form
        className="card card--padded"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
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
            <PendingLabel pending={pending} idle="Create organization" busy="Creating…" />
          </button>
        </div>
      </form>
    </main>
  );
}
