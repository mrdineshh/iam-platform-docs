import { useCallback, useEffect, useState } from "react";
import {
  deleteScimConnection,
  listScimConnections,
  saveScimConnection,
  syncScimConnection,
  testScimConnection,
  type ScimConnection,
} from "@/lib/provisioning";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import { Alert, PendingLabel, StatusBadge } from "@/components/ui";
import { useConfirm, useToast } from "@/components/feedback";

/**
 * Per-app SCIM 2.0 provisioning: when connected, the platform creates, suspends,
 * reactivates and deletes this app's users automatically as the platform's own
 * users change. The access token is write-only (kept in the secret store, never
 * shown again).
 */
export function AppProvisioningPanel({ kind, appId }: { kind: "OIDC" | "SAML"; appId: string }) {
  const session = loadSession()!;
  const toast = useToast();
  const confirm = useConfirm();
  const [connection, setConnection] = useState<ScimConnection | null | undefined>(undefined);
  const [baseUrl, setBaseUrl] = useState("");
  const [token, setToken] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"save" | "test" | "sync" | "remove" | null>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const all = await listScimConnections(session.tenantId, session.token);
      const mine = all.find((c) => c.appId === appId && c.appKind === kind) ?? null;
      setConnection(mine);
      if (mine) {
        setBaseUrl(mine.baseUrl);
        setEnabled(mine.enabled);
      }
    } catch (err) {
      setError(errorMessage(err));
      setConnection(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appId, kind]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setTestResult(null);
    if (!baseUrl.trim()) {
      setError("Enter the app's SCIM URL.");
      return;
    }
    if (!connection && !token.trim()) {
      setError("Enter the access token the app gave you.");
      return;
    }
    setBusy("save");
    try {
      const saved = await saveScimConnection(session.tenantId, kind, appId, baseUrl.trim(), token.trim(), enabled, session.token);
      setConnection(saved);
      setToken("");
      toast.success("Provisioning connection saved.");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  async function handleTest() {
    if (!connection) return;
    setBusy("test");
    setTestResult(null);
    try {
      setTestResult(await testScimConnection(session.tenantId, connection.id, session.token));
    } catch (err) {
      setTestResult({ ok: false, message: errorMessage(err) });
    } finally {
      setBusy(null);
    }
  }

  async function handleSync() {
    if (!connection) return;
    const ok = await confirm({
      title: "Send all users to this app?",
      message: "Every user in your organization is created in the app (suspended users are skipped). Users already there are linked, not duplicated.",
      confirmLabel: "Sync users",
    });
    if (!ok) return;
    setBusy("sync");
    try {
      const r = await syncScimConnection(session.tenantId, connection.id, session.token);
      if (r.failed > 0) toast.error(`${r.succeeded} of ${r.users} users synced, ${r.failed} failed. Open a user's Apps to see why.`);
      else toast.success(`${r.succeeded} of ${r.users} users are up to date in the app.`);
      await load();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  async function handleRemove() {
    if (!connection) return;
    const ok = await confirm({
      title: "Remove provisioning for this app?",
      message: "Users stay in the app as they are, but changes here will no longer be sent to it.",
      confirmLabel: "Remove",
      danger: true,
    });
    if (!ok) return;
    setBusy("remove");
    try {
      await deleteScimConnection(session.tenantId, connection.id, session.token);
      setConnection(null);
      setBaseUrl("");
      setToken("");
      setTestResult(null);
      toast.success("Provisioning removed.");
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="table-details__groups">
      <strong>
        Automatic provisioning (SCIM){" "}
        {connection && (connection.enabled ? <StatusBadge tone="success">On</StatusBadge> : <StatusBadge tone="neutral">Paused</StatusBadge>)}
      </strong>
      <p className="hint" style={{ marginTop: 0 }}>
        Create, suspend and delete this app's users automatically when they change here. The app must offer a SCIM 2.0
        endpoint and an access token.
      </p>

      {error && <Alert kind="error">{error}</Alert>}
      {connection === undefined ? (
        <p className="hint">Loading…</p>
      ) : (
        <>
          {connection && (
            <p className="hint">
              {connection.accountsActive} active, {connection.accountsSuspended} suspended
              {connection.accountsFailed > 0 && <>, <strong>{connection.accountsFailed} failed</strong></>}
            </p>
          )}

          <form onSubmit={(e) => void handleSave(e)} className="form-grid">
            <label className="login-form__field form-grid__full">
              SCIM URL
              <input
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="https://app.example.com/scim/v2"
                inputMode="url"
              />
              <span className="field-hint">Must be https and publicly reachable.</span>
            </label>
            <label className="login-form__field form-grid__full">
              Access token
              <input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder={connection?.hasToken ? "Stored. Leave blank to keep it." : "Paste the app's SCIM token"}
                autoComplete="off"
              />
            </label>
            <label className="checkbox-field form-grid__full">
              <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
              Send changes to this app
            </label>

            <div className="form-grid__full row-actions" style={{ justifyContent: "flex-start", flexWrap: "wrap" }}>
              <button type="submit" className="btn-sm" disabled={busy !== null}>
                <PendingLabel pending={busy === "save"} idle={connection ? "Save changes" : "Connect"} busy="Saving…" />
              </button>
              {connection && (
                <>
                  <button type="button" className="btn-secondary btn-sm" disabled={busy !== null} onClick={() => void handleTest()}>
                    <PendingLabel pending={busy === "test"} idle="Test connection" busy="Testing…" />
                  </button>
                  <button type="button" className="btn-secondary btn-sm" disabled={busy !== null} onClick={() => void handleSync()}>
                    <PendingLabel pending={busy === "sync"} idle="Sync all users" busy="Syncing…" />
                  </button>
                  <button type="button" className="btn-danger btn-sm" disabled={busy !== null} onClick={() => void handleRemove()}>
                    <PendingLabel pending={busy === "remove"} idle="Remove" busy="Removing…" />
                  </button>
                </>
              )}
            </div>
          </form>

          {testResult && <Alert kind={testResult.ok ? "success" : "error"}>{testResult.message}</Alert>}
        </>
      )}
    </div>
  );
}

function errorMessage(err: unknown): string {
  if (err instanceof UpstreamError) {
    if (err.status === 400) return err.message || "Some of those values are not valid.";
    if (err.status === 401) return "Your session expired. Please sign in again.";
    if (err.status === 403) return "You don't have permission to do this.";
    return "This is temporarily unavailable. Please try again.";
  }
  return "This is temporarily unavailable. Please try again.";
}
