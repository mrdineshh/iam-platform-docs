import type { SessionSummary } from "@/lib/sessions";
import { EmptyState, PendingLabel, StatusBadge } from "@/components/ui";

/**
 * Table of live sessions with a per-row "Sign out" button. Shared by the
 * admin's per-user Sessions dialog and the user's own My Security page.
 */
export function SessionList({
  sessions,
  revokingId,
  onRevoke,
}: {
  sessions: SessionSummary[];
  revokingId: string | null;
  onRevoke: (session: SessionSummary) => void;
}) {
  if (sessions.length === 0) {
    return <EmptyState title="No active sessions" description="This user is not signed in anywhere right now." />;
  }

  return (
    <div className="card table-card">
      <table>
        <thead>
          <tr>
            <th>IP address</th>
            <th>Signed in</th>
            <th>Expires</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((s) => (
            <tr key={s.sessionId}>
              <td>
                {s.sourceIp ?? "Unknown"} {s.current && <StatusBadge tone="success">This session</StatusBadge>}
              </td>
              <td>{new Date(s.issuedAt).toLocaleString()}</td>
              <td>{new Date(s.expiresAt).toLocaleString()}</td>
              <td>
                <div className="row-actions">
                  <button
                    type="button"
                    className="btn-danger btn-sm"
                    disabled={revokingId === s.sessionId}
                    onClick={() => onRevoke(s)}
                  >
                    <PendingLabel pending={revokingId === s.sessionId} idle="Sign out" busy="Signing out…" />
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
