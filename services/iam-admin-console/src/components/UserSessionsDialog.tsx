import { useCallback, useEffect, useState } from "react";
import { listUserSessions, revokeAllUserSessions, revokeUserSession, type SessionSummary } from "@/lib/sessions";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import { Alert, PendingLabel, SkeletonRows } from "@/components/ui";
import { SessionList } from "@/components/SessionList";
import { useConfirm, useToast } from "@/components/feedback";

/** Admin view of one user's live sessions, with "sign out everywhere". */
export function UserSessionsDialog({
  userId,
  userLabel,
  onClose,
}: {
  userId: string;
  userLabel: string;
  onClose: () => void;
}) {
  const session = loadSession()!;
  const toast = useToast();
  const confirm = useConfirm();
  const [sessions, setSessions] = useState<SessionSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [revokingAll, setRevokingAll] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      setSessions(await listUserSessions(session.tenantId, userId, session.token));
    } catch (err) {
      setError(errorMessage(err));
      setSessions([]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function handleRevoke(s: SessionSummary) {
    setRevokingId(s.sessionId);
    try {
      await revokeUserSession(session.tenantId, userId, s.sessionId, session.token);
      toast.success("Session signed out.");
      await load();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setRevokingId(null);
    }
  }

  async function handleRevokeAll() {
    const ok = await confirm({
      title: "Sign out everywhere?",
      message: `${userLabel} will be signed out of every device and app right away and will need to sign in again.`,
      confirmLabel: "Sign out everywhere",
      danger: true,
    });
    if (!ok) return;
    setRevokingAll(true);
    try {
      const result = await revokeAllUserSessions(session.tenantId, userId, session.token);
      toast.success(`Signed out of ${result.revoked} session${result.revoked === 1 ? "" : "s"}.`);
      await load();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setRevokingAll(false);
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div
        className="modal modal--wide"
        role="dialog"
        aria-modal="true"
        aria-labelledby="sessions-title"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <h3 id="sessions-title" className="modal__title">
          Active sessions
        </h3>
        <p className="modal__body" style={{ marginTop: 0 }}>
          {userLabel}
        </p>

        {error && <Alert kind="error">{error}</Alert>}

        <div style={{ marginTop: 16 }}>
          {sessions === null ? (
            <SkeletonRows rows={2} />
          ) : (
            <SessionList sessions={sessions} revokingId={revokingId} onRevoke={(s) => void handleRevoke(s)} />
          )}
        </div>

        <div className="modal__actions">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Close
          </button>
          <button
            type="button"
            className="btn-solid-danger"
            disabled={revokingAll || !sessions || sessions.length === 0}
            onClick={() => void handleRevokeAll()}
          >
            <PendingLabel pending={revokingAll} idle="Sign out everywhere" busy="Signing out…" />
          </button>
        </div>
      </div>
    </div>
  );
}

function errorMessage(err: unknown): string {
  if (err instanceof UpstreamError) {
    if (err.status === 401) return "Your session expired. Please sign in again.";
    if (err.status === 403) return "You don't have permission to do this.";
    if (err.status === 404) return "That session has already ended.";
    return "This is temporarily unavailable. Please try again.";
  }
  return "This is temporarily unavailable. Please try again.";
}
