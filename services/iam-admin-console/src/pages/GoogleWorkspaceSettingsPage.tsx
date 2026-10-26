import { useEffect, useState } from "react";
import { getGoogleWorkspaceConfig, setGoogleWorkspaceConfig, type GoogleWorkspaceConfig } from "@/lib/googleWorkspace";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";

/**
 * One-time setup so that creating a user here also creates the matching
 * Google Workspace account (Admin SDK Directory API) -- see
 * GoogleWorkspaceDirectoryClient's own doc comment (iam-tenant-svc) for the
 * full explanation of why a random Google-side password is generated and
 * never shown: once the account's org unit is on an SSO profile in
 * redirect mode, only this platform's own password ever matters for
 * sign-in day to day.
 */
export function GoogleWorkspaceSettingsPage() {
  const session = loadSession()!;
  const [existing, setExisting] = useState<GoogleWorkspaceConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [domain, setDomain] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [orgUnitPath, setOrgUnitPath] = useState("");
  const [serviceAccountJson, setServiceAccountJson] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const config = await getGoogleWorkspaceConfig(session.tenantId, session.token);
        setExisting(config);
        if (config) {
          setDomain(config.domain);
          setAdminEmail(config.adminEmail);
          setOrgUnitPath(config.orgUnitPath ?? "");
        }
      } catch (err) {
        setError(errorMessage(err));
      } finally {
        setLoading(false);
      }
      // eslint-disable-next-line react-hooks/exhaustive-deps
    })();
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!domain.trim() || !adminEmail.trim() || !serviceAccountJson.trim()) {
      setError("Enter the domain, admin email, and the service account's JSON key.");
      return;
    }
    setSaving(true);
    setSaved(false);
    try {
      const config = await setGoogleWorkspaceConfig(
        session.tenantId, domain.trim(), adminEmail.trim(), orgUnitPath.trim(), serviceAccountJson.trim(), session.token,
      );
      setExisting(config);
      setServiceAccountJson("");
      setSaved(true);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <main className="page">
      <h1>Google Workspace</h1>
      <p className="hint">
        Once configured, creating a user here also creates the matching Google Workspace account automatically —
        you'll only ever need this platform's own password to sign in, not a separate Google one.
      </p>

      {loading ? (
        <p>Loading…</p>
      ) : (
        <>
          {existing && (
            <div className="callout">
              <p>
                Configured for <strong>{existing.domain}</strong>, impersonating <strong>{existing.adminEmail}</strong>
                {existing.orgUnitPath ? (
                  <>
                    {" "}
                    into <code>{existing.orgUnitPath}</code>
                  </>
                ) : null}
                .
              </p>
            </div>
          )}

          {error && (
            <p role="alert" className="login-form__error">
              {error}
            </p>
          )}
          {saved && <p className="hint">Saved.</p>}

          <form className="setup-form" onSubmit={(e) => void handleSubmit(e)}>
            <p className="hint">
              One-time Google-side setup needed before this works: create a service account in Google Cloud Console,
              enable the Admin SDK API, then authorize that service account for domain-wide delegation in Workspace
              Admin console (Security → API controls → Domain-wide delegation) with scope{" "}
              <code>https://www.googleapis.com/auth/admin.directory.user</code>.
            </p>

            <label>
              Workspace domain
              <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="demo.econz.net" required />
            </label>

            <label>
              Admin email to impersonate
              <input
                value={adminEmail}
                onChange={(e) => setAdminEmail(e.target.value)}
                placeholder="a real super admin on this domain"
                required
              />
            </label>

            <label>
              Org unit path for new users
              <input
                value={orgUnitPath}
                onChange={(e) => setOrgUnitPath(e.target.value)}
                placeholder="/Ratnesh Test (optional — blank places new users in the root OU)"
              />
            </label>

            <label>
              Service account JSON key
              <textarea
                value={serviceAccountJson}
                onChange={(e) => setServiceAccountJson(e.target.value)}
                placeholder="Paste the full contents of the downloaded JSON key file"
                rows={8}
                required
              />
            </label>

            <button type="submit" disabled={saving}>
              {saving ? "Saving…" : existing ? "Update" : "Save"}
            </button>
          </form>
        </>
      )}
    </main>
  );
}

function errorMessage(err: unknown): string {
  if (err instanceof UpstreamError) {
    if (err.status === 401) return "Your session expired. Please sign in again.";
    if (err.status === 403) return "You don't have permission to do this.";
    if (err.status === 400) return err.message || "Invalid service account JSON.";
    return "This is temporarily unavailable. Please try again.";
  }
  return "This is temporarily unavailable. Please try again.";
}
