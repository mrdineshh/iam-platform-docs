import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listTenantUsers, impersonate, type AdminUserListEntry } from "@/lib/impersonate";
import { loadSession, startImpersonation } from "@/lib/session";
import { UpstreamError } from "@/lib/http";

/**
 * Admin-only "Switch to user" picker. Every switch is server-side audited
 * (iam-tenant-svc's ImpersonateController publishes identity.impersonated)
 * -- this page is just the UI, the real guard and the audit trail live on
 * the backend, not here.
 */
export function SwitchUserPage() {
  const session = loadSession()!;
  const navigate = useNavigate();
  const [users, setUsers] = useState<AdminUserListEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [switching, setSwitching] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      setLoading(true);
      setError(null);
      try {
        setUsers(await listTenantUsers(session.tenantId, session.token));
      } catch (err) {
        setError(errorMessage(err));
      } finally {
        setLoading(false);
      }
      // eslint-disable-next-line react-hooks/exhaustive-deps
    })();
  }, []);

  async function handleSwitch(userId: string) {
    setError(null);
    setSwitching(userId);
    try {
      const result = await impersonate(session.tenantId, userId, session.token);
      startImpersonation({
        token: result.token,
        role: result.role,
        tenantId: session.tenantId,
        tenantName: session.tenantName,
        email: result.email,
        displayName: result.displayName,
      });
      navigate("/");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSwitching(null);
    }
  }

  return (
    <main className="page">
      <h1>Switch to user</h1>
      <p className="hint">You'll be signed in as the selected user. Every switch is logged.</p>

      {error && (
        <p role="alert" className="login-form__error">
          {error}
        </p>
      )}

      {loading ? (
        <p>Loading…</p>
      ) : users.length === 0 ? (
        <p>No other users in this tenant yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.displayName}</td>
                <td>{u.email}</td>
                <td>{u.role}</td>
                <td>{u.status}</td>
                <td>
                  <button type="button" disabled={switching === u.id} onClick={() => void handleSwitch(u.id)}>
                    {switching === u.id ? "Switching…" : "Switch to this user"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}

function errorMessage(err: unknown): string {
  if (err instanceof UpstreamError) {
    if (err.status === 401) return "Your session expired. Please sign in again.";
    if (err.status === 403) return "You don't have permission to do this.";
    if (err.status === 404) return "That user could not be found.";
    return "This is temporarily unavailable. Please try again.";
  }
  return "This is temporarily unavailable. Please try again.";
}
