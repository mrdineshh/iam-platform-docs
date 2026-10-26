import { useState } from "react";
import QRCode from "qrcode";
import { enrollMy2fa, verifyMy2fa } from "@/lib/device";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";

/**
 * Self-service TOTP enrollment. The QR is rendered client-side (qrcode
 * package, canvas -> data URL) from the provisioningUri this browser
 * receives directly from its own /me/2fa/enroll call -- the raw secret
 * never passes through anyone else, admin included.
 */
export function MySecurityPage() {
  const session = loadSession()!;
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [verified, setVerified] = useState(false);

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
      } else {
        setError("That code didn't match. Try the current code from your app.");
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setPending(false);
    }
  }

  return (
    <main className="page">
      <h1>My Security</h1>

      {error && (
        <p role="alert" className="login-form__error">
          {error}
        </p>
      )}

      {verified ? (
        <p>Two-factor authentication is set up. Use your authenticator app's code the next time you sign in.</p>
      ) : !qrDataUrl ? (
        <>
          <p>Set up an authenticator app (Google Authenticator, Authy, etc.) for two-factor sign-in.</p>
          <button type="button" onClick={() => void startEnrollment()} disabled={pending}>
            {pending ? "Starting…" : "Set up authenticator app"}
          </button>
        </>
      ) : (
        <>
          <p>Scan this in your authenticator app:</p>
          <div className="qr-wrap">
            <img src={qrDataUrl} alt="TOTP QR code" width={200} height={200} />
          </div>
          {secret && (
            <p>
              Can't scan? Enter this key manually (time-based): <code>{secret}</code>
            </p>
          )}
          <form className="login-form" onSubmit={(e) => void submitCode(e)}>
            <label className="login-form__field">
              Enter the 6-digit code to confirm
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
            <div className="login-form__buttons">
              <button type="submit" disabled={pending}>
                {pending ? "Verifying…" : "Confirm"}
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
    return "This is temporarily unavailable. Please try again.";
  }
  return "This is temporarily unavailable. Please try again.";
}
