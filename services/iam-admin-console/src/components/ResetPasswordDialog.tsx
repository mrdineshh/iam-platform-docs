import { useEffect, useState } from "react";
import { resetUserPassword, type ResetPasswordResult } from "@/lib/identity";
import { generatePassword } from "@/lib/generatePassword";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import { Alert, PendingLabel } from "@/components/ui";
import { useToast } from "@/components/feedback";

/** The Google side of the answer. A user who is not a synced Google user gets a clear warning that only the platform changed. */
function GoogleOutcome({ result }: { result: ResetPasswordResult }) {
  switch (result.google) {
    case "RESET":
      return <Alert kind="success">The password was also changed in Google Workspace.</Alert>;
    case "NOT_REQUESTED":
      return <Alert kind="info">The Google Workspace password was not changed (you did not tick the box).</Alert>;
    case "FAILED":
      return (
        <Alert kind="error">
          The platform password was changed, but Google Workspace refused the change{result.googleDetail ? `: ${result.googleDetail}` : ""}. Change it
          in Google Admin if this user needs it.
        </Alert>
      );
    default:
      return (
        <Alert kind="error">
          Only the IAM platform password was changed. This user is not a synced Google Workspace user, so nothing was changed in Google Workspace.
        </Alert>
      );
  }
}

/**
 * Admin sets a new platform password for one user (spec 13.2: confirmation, required reason, audited). The new password is
 * shown once, after success, so the admin can hand it over; it is never stored for retrieval.
 */
export function ResetPasswordDialog({
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
  const [password, setPassword] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [done, setDone] = useState<{ password: string; result: ResetPasswordResult } | null>(null);
  const [alsoGoogle, setAlsoGoogle] = useState(false);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function submit() {
    setError(null);
    if (password.length < 8) {
      setError("The password must be at least 8 characters.");
      return;
    }
    setPending(true);
    try {
      const result = await resetUserPassword(session.tenantId, userId, password, reason.trim(), alsoGoogle, session.token);
      setDone({ password, result });
      toast.success(`Password reset for ${userLabel}.`);
    } catch (err) {
      if (err instanceof UpstreamError && (err.status === 400 || err.status === 403 || err.status === 404)) {
        // 400 carries the tenant's own password rule, worded by the server.
        setError(err.message);
      } else {
        setError("Could not reset the password. Please try again.");
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={() => onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="reset-pw-title" onMouseDown={(e) => e.stopPropagation()}>
        <h3 id="reset-pw-title" className="modal__title">
          Reset password
        </h3>
        {done ? (
          <>
            <div className="modal__body">
              <p>
                The password for <strong>{userLabel}</strong> was changed and their sessions were signed out. Send them the new
                password now; it is not shown again.
              </p>
              <p>
                <code style={{ wordBreak: "break-all" }}>{done.password}</code>
              </p>
              <GoogleOutcome result={done.result} />
            </div>
            <div className="modal__actions">
              <button
                type="button"
                className="btn-secondary"
                onClick={() => void navigator.clipboard.writeText(done.password).then(() => toast.success("Password copied"))}
              >
                Copy
              </button>
              <button type="button" onClick={() => onClose()}>
                Done
              </button>
            </div>
          </>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void submit();
            }}
          >
            <div className="modal__body">
              <p>
                Set a new password for <strong>{userLabel}</strong>. Their current sessions are signed out. Only the platform
                password changes, unless you tick the Google Workspace box below.
              </p>
              {error && <Alert kind="error">{error}</Alert>}
              <label className="login-form__field" style={{ marginTop: 12 }}>
                <span>New password</span>
                <div style={{ display: "flex", gap: 8 }}>
                  <input
                    type="text"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                    required
                    style={{ flex: 1 }}
                  />
                  <button type="button" className="btn-secondary" onClick={() => setPassword(generatePassword())}>
                    Generate
                  </button>
                </div>
              </label>
              <label className="checkbox-field" style={{ marginTop: 12 }}>
                <input type="checkbox" checked={alsoGoogle} onChange={(e) => setAlsoGoogle(e.target.checked)} />
                Also set this password in Google Workspace (synced Google users only)
              </label>
              <label className="login-form__field" style={{ marginTop: 12 }}>
                <span>Reason (required, kept in the audit log)</span>
                <textarea
                  value={reason}
                  maxLength={500}
                  rows={3}
                  required
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="For example: user forgot their password"
                />
              </label>
            </div>
            <div className="modal__actions">
              <button type="button" className="btn-secondary" onClick={() => onClose()}>
                Cancel
              </button>
              <button type="submit" disabled={pending || !password || !reason.trim()}>
                <PendingLabel pending={pending} idle="Reset password" busy="Resetting…" />
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
