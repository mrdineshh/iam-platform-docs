import { useCallback, useEffect, useState } from "react";
import QRCode from "qrcode";
import { enrollMy2fa, verifyMy2fa } from "@/lib/device";
import { listMySessions, revokeMyOtherSessions, revokeMySession, type SessionSummary } from "@/lib/sessions";
import { clearSession, loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import { Alert, PageHeader, PendingLabel, SkeletonRows, StatusBadge } from "@/components/ui";
import { SessionList } from "@/components/SessionList";
import { useConfirm, useToast } from "@/components/feedback";

/**
 * Self-service security: TOTP enrollment and active-session management. The
 * QR is rendered client-side (qrcode package, canvas -> data URL) from the
 * provisioningUri this browser receives directly from its own
 * /me/2fa/enroll call -- the raw secret never passes through anyone else,
 * admin included.
 */
export function MySecurityPage() {
  const session = loadSession()!;
  const toast = useToast();
  const confirm = useConfirm();
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [verified, setVerified] = useState(false);

  const [sessions, setSessions] = useState<SessionSummary[] | null>(null);
  const [sessionsError, setSessionsError] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [revokingOthers, setRevokingOthers] = useState(false);

  const loadSessions = useCallback(async () => {
    setSessionsError(null);
    try {
      setSessions(await listMySessions(session.token));
    } catch (err) {
      setSessionsError(errorMessage(err));
      setSessions([]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    void loadSessions();
  }, [loadSessions]);

  async function startEnrollment() {
    setError(null);
    setPending(true);
    try {
      const result = await enrollMy2fa(session.token);
      setSecret(result.totpSecret);
      setQrDataUrl(await QRCode.toDataURL(result.provisioningUri));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setPending(false);
    }
  }

  async function submitCode(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!/^\d{6}$/.test(code)) {
      setError("Enter the 6-digit code your authenticator app is showing.");
      return;
    }
    setPending(true);
    try {
      const result = await verifyMy2fa(code, session.token);
      if (result.valid) {
        setVerified(true);
        toast.success("Two-factor authentication is set up.");
      } else {
        setError("That code didn't match. Try the current code from your app.");
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setPending(false);
    }
  }

  async function handleRevoke(s: SessionSummary) {
    if (s.current) {
      const ok = await confirm({
        title: "Sign out of this session?",
        message: "You'll be signed out of this browser and sent to the sign-in page.",
        confirmLabel: "Sign out",
        danger: true,
      });
      if (!ok) return;
    }
    setRevokingId(s.sessionId);
    try {
      await revokeMySession(s.sessionId, session.token);
      if (s.current) {
        clearSession();
        window.location.assign("/login");
        return;
      }
      toast.success("Session signed out.");
      await loadSessions();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setRevokingId(null);
    }
  }

  async function handleRevokeOthers() {
    const ok = await confirm({
      title: "Sign out of all other devices?",
      message: "Every other browser and device signed in as you will be signed out. This session stays signed in.",
      confirmLabel: "Sign out others",
      danger: true,
    });
    if (!ok) return;
    setRevokingOthers(true);
    try {
      const result = await revokeMyOtherSessions(session.token);
      toast.success(`Signed out of ${result.revoked} other session${result.revoked === 1 ? "" : "s"}.`);
      await loadSessions();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setRevokingOthers(false);
    }
  }

  const otherSessions = sessions?.filter((s) => !s.current).length ?? 0;

  return (
    <main className="page page--narrow">
      <PageHeader title="My Security" subtitle="Manage how you sign in and where you're signed in." />

      <section className="card card--padded" style={{ marginBottom: 24 }}>
        <h3 className="card__title">
          Two-factor authentication {verified && <StatusBadge tone="success">Set up</StatusBadge>}
        </h3>

        {error && <Alert kind="error">{error}</Alert>}

        {verified ? (
          <p className="card__desc" style={{ marginBottom: 0 }}>
            Use your authenticator app's code the next time you sign in.
          </p>
        ) : !qrDataUrl ? (
          <>
            <p className="card__desc">
              Set up an authenticator app (Google Authenticator, Authy, etc.) for two-factor sign-in.
            </p>
            <button type="button" onClick={() => void startEnrollment()} disabled={pending}>
              <PendingLabel pending={pending} idle="Set up authenticator app" busy="Starting…" />
            </button>
          </>
        ) : (
          <>
            <p className="card__desc">Scan this code in your authenticator app, then enter the 6-digit code it shows.</p>
            <div className="qr-wrap">
              <img src={qrDataUrl} alt="TOTP QR code" width={200} height={200} />
            </div>
            {secret && (
              <p className="hint">
                Can't scan? Enter this key manually (time-based): <code>{secret}</code>
              </p>
            )}
            <form onSubmit={(e) => void submitCode(e)}>
              <label className="login-form__field" style={{ maxWidth: 260 }}>
                6-digit code
                <input
                  type="text"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  inputMode="numeric"
                  pattern="\d{6}"
                  maxLength={6}
                  placeholder="123456"
                  autoComplete="one-time-code"
                  required
                />
              </label>
              <div className="form-actions" style={{ justifyContent: "flex-start" }}>
                <button type="submit" disabled={pending}>
                  <PendingLabel pending={pending} idle="Confirm" busy="Verifying…" />
                </button>
              </div>
            </form>
          </>
        )}
      </section>

      <section>
        <div className="section-title" style={{ marginTop: 0 }}>
          <h2>Active sessions</h2>
          <button
            type="button"
            className="btn-secondary btn-sm"
            disabled={revokingOthers || otherSessions === 0}
            onClick={() => void handleRevokeOthers()}
          >
            <PendingLabel pending={revokingOthers} idle="Sign out of all other devices" busy="Signing out…" />
          </button>
        </div>
        <p className="hint" style={{ marginTop: 0 }}>
          Browsers and devices currently signed in as you. Sign out any you don't recognize.
        </p>
        {sessionsError && <Alert kind="error">{sessionsError}</Alert>}
        {sessions === null ? (
          <SkeletonRows rows={2} />
        ) : (
          <SessionList sessions={sessions} revokingId={revokingId} onRevoke={(s) => void handleRevoke(s)} />
        )}
      </section>
    </main>
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
