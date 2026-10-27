import { useCallback, useEffect, useState } from "react";
import {
  getUserProvisioning,
  retryUserProvisioning,
  summarizeTargets,
  type UserProvisioningStatus,
} from "@/lib/provisioning";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import { Alert, EmptyState, PendingLabel, SkeletonRows, StatusBadge } from "@/components/ui";
import { useToast } from "@/components/feedback";

function badge(s: UserProvisioningStatus) {
  if (s.error) return <StatusBadge tone="danger">Failed</StatusBadge>;
  switch (s.state) {
    case "ACTIVE":
      return <StatusBadge tone="success">Active</StatusBadge>;
    case "SUSPENDED":
      return <StatusBadge tone="warning">Suspended</StatusBadge>;
    case "PENDING":
      return <StatusBadge tone="warning">Pending</StatusBadge>;
    default:
      return <StatusBadge tone="neutral">Not in app</StatusBadge>;
  }
}

/** Where one user stands in each SCIM-connected app, with the app's error if a push failed, and a retry. */
export function UserProvisioningDialog({
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
  const [statuses, setStatuses] = useState<UserProvisioningStatus[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retrying, setRetrying] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      setStatuses(await getUserProvisioning(session.tenantId, userId, session.token));
    } catch (err) {
      setError(errorMessage(err));
      setStatuses([]);
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

  async function handleRetry() {
    setRetrying(true);
    try {
      const results = await retryUserProvisioning(session.tenantId, userId, session.token);
      const { done, problems } = summarizeTargets(results);
      if (problems.length > 0) toast.error(problems.join(" | "));
      else toast.success(done ?? "Everything is already up to date.");
      await load();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setRetrying(false);
    }
  }

  const hasFailure = statuses?.some((s) => s.error) ?? false;

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div
        className="modal modal--wide"
        role="dialog"
        aria-modal="true"
        aria-labelledby="prov-title"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <h3 id="prov-title" className="modal__title">
          Connected apps
        </h3>
        <p className="modal__body" style={{ marginTop: 0 }}>
          {userLabel}
        </p>

        {error && <Alert kind="error">{error}</Alert>}

        <div style={{ marginTop: 16 }}>
          {statuses === null ? (
            <SkeletonRows rows={2} />
          ) : statuses.length === 0 ? (
            <EmptyState
              title="No apps are connected for provisioning"
              description="On the Applications page, open an app and connect its SCIM endpoint. Users are then created, suspended and removed there automatically."
            />
          ) : (
            <div className="card table-card">
              <table>
                <thead>
                  <tr>
                    <th>App</th>
                    <th>Status</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {statuses.map((s) => (
                    <tr key={s.connectionId}>
                      <td>{s.appName}</td>
                      <td>{badge(s)}</td>
                      <td className="cell-user__sub" style={{ whiteSpace: "normal" }}>
                        {s.error ?? (s.updatedAt ? `Updated ${new Date(s.updatedAt).toLocaleString()}` : "")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="modal__actions">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Close
          </button>
          {statuses && statuses.length > 0 && (
            <button type="button" disabled={retrying} onClick={() => void handleRetry()}>
              <PendingLabel pending={retrying} idle={hasFailure ? "Retry failed" : "Sync now"} busy="Syncing…" />
            </button>
          )}
        </div>
      </div>
    </div>
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
