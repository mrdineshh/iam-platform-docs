import { useEffect, useState } from "react";
import { getGoogleWorkspaceConfig, setGoogleWorkspaceConfig, type GoogleWorkspaceConfig } from "@/lib/googleWorkspace";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import { Alert, PageHeader, PendingLabel, SkeletonRows, StatusBadge } from "@/components/ui";
import { useToast } from "@/components/feedback";

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
  const toast = useToast();
  const [existing, setExisting] = useState<GoogleWorkspaceConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [domain, setDomain] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [orgUnitPath, setOrgUnitPath] = useState("");
  const [serviceAccountJson, setServiceAccountJson] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

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
    try {
      const config = await setGoogleWorkspaceConfig(
        session.tenantId, domain.trim(), adminEmail.trim(), orgUnitPath.trim(), serviceAccountJson.trim(), session.token,
      );
      setExisting(config);
      setServiceAccountJson("");
      toast.success("Google Workspace settings saved.");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <main className="page page--narrow">
      <PageHeader
        title="Google Workspace"
        subtitle="Once connected, creating a user here also creates the matching Google Workspace account automatically. Users only ever need this platform's password to sign in."
        actions={
          loading ? undefined : existing ? (
            <StatusBadge tone="success">Connected</StatusBadge>
          ) : (
            <StatusBadge tone="warning">Not configured</StatusBadge>
          )
        }
      />

      {loading ? (
        <SkeletonRows rows={4} />
      ) : (
        <>
          {existing && (
            <Alert kind="info">
              Connected to <strong>{existing.domain}</strong>, acting as <strong>{existing.adminEmail}</strong>
              {existing.orgUnitPath ? (
                <>
                  , creating new users in <code>{existing.orgUnitPath}</code>
                </>
              ) : null}
              . To change anything, re-enter the service account key below and save.
            </Alert>
          )}

          {error && <Alert kind="error">{error}</Alert>}

          <section className="card card--padded" style={{ marginBottom: 24 }}>
            <h3 className="card__title">Before you start</h3>
            <p className="card__desc">One-time setup on the Google side so this platform is allowed to create accounts.</p>
            <ol className="steps">
              <li>In Google Cloud Console, create a service account and download its JSON key.</li>
              <li>Enable the <strong>Admin SDK API</strong> for that project.</li>
              <li>
                In Google Admin, open Security → API controls → <strong>Domain-wide delegation</strong> and authorize the
                service account's client ID with the scope <code>https://www.googleapis.com/auth/admin.directory.user</code>.
              </li>
            </ol>
          </section>

          <form className="card card--padded" onSubmit={(e) => void handleSubmit(e)}>
            <h3 className="card__title">Connection settings</h3>
            <p className="card__desc">The key is stored encrypted in the platform's secret store, never in the database.</p>

            <div className="form-grid">
              <label className="login-form__field">
                Workspace domain
                <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="demo.econz.net" required />
              </label>

              <label className="login-form__field">
                Admin email to act as
                <input
                  value={adminEmail}
                  onChange={(e) => setAdminEmail(e.target.value)}
                  placeholder="A super admin on this domain"
                  required
                />
              </label>

              <label className="login-form__field form-grid__full">
                Org unit path for new users
                <input
                  value={orgUnitPath}
                  onChange={(e) => setOrgUnitPath(e.target.value)}
                  placeholder="/Ratnesh Test"
                />
                <span className="field-hint">Optional. Leave blank to place new users in the root org unit.</span>
              </label>

              <label className="login-form__field form-grid__full">
                Service account JSON key
                <textarea
                  value={serviceAccountJson}
                  onChange={(e) => setServiceAccountJson(e.target.value)}
                  placeholder="Paste the full contents of the downloaded JSON key file"
                  rows={8}
                  required
                />
              </label>
            </div>

            <div className="form-actions">
              <button type="submit" disabled={saving}>
                <PendingLabel pending={saving} idle={existing ? "Update connection" : "Save connection"} busy="Saving…" />
              </button>
            </div>
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
