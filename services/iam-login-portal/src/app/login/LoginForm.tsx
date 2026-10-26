"use client";

import { useActionState, useEffect, useRef, useState } from "react";
import { useFormStatus } from "react-dom";
import QRCode from "qrcode";
import { loginAction, precheckAction } from "./actions";
import { initialLoginFormState } from "./types";

interface Props {
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  tenantOverride: string | null;
  tenantName: string;
}

type Step = "username" | "password" | "enroll" | "code" | "submitting-no-code";

/**
 * Four-screen wizard (username -> password -> [enroll QR | code] ->
 * submit), a client-side presentational layer over iam-auth-svc's single
 * /login call. The password step calls the read-only /login/precheck
 * action first to find out which of three screens comes next: no further
 * screen at all (mfaRequired=false -- submits immediately), a QR +
 * authenticator-code screen (first-time enrollment, no device yet), or the
 * existing code/push screen (an active device already exists). Precheck
 * never triggers a push send or issues a session itself -- only the final
 * submit (loginAction, same as before) does that.
 */
export function LoginForm({ clientId, redirectUri, scope, state, tenantOverride, tenantName }: Props) {
  const [formState, formAction] = useActionState(loginAction, initialLoginFormState);
  const [intent, setIntent] = useState<"totp" | "push">("totp");
  const [step, setStep] = useState<Step>("username");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [stepError, setStepError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const formRef = useRef<HTMLFormElement>(null);

  // mfaRequired=false: there's nothing left for the user to do, so submit
  // the real form the moment that step is reached, with no totpCode.
  useEffect(() => {
    if (step === "submitting-no-code") {
      formRef.current?.requestSubmit();
    }
  }, [step]);

  async function handlePasswordNext() {
    if (!password) {
      setStepError("Enter your password.");
      return;
    }
    setStepError(null);
    setChecking(true);
    try {
      const result = await precheckAction({ tenantOverride, email, password });
      if (!result.ok) {
        setStepError(result.error);
        return;
      }
      if (!result.mfaRequired) {
        setStep("submitting-no-code");
        return;
      }
      if (result.enrollmentRequired) {
        setQrDataUrl(result.provisioningUri ? await QRCode.toDataURL(result.provisioningUri) : null);
        setStep("enroll");
        return;
      }
      setStep("code");
    } finally {
      setChecking(false);
    }
  }

  const stepIndex = step === "username" ? 0 : step === "password" ? 1 : 2;

  return (
    <>
      <div className="login-page__brand">
        <span className="login-page__brand-mark">IAM</span>
        <span className="login-page__brand-name">Platform</span>
      </div>
      <form ref={formRef} action={formAction} className="login-form">
        <h1>Sign in to {tenantName}</h1>
        <ol className="login-steps" aria-hidden="true">
          <li className={stepIndex >= 0 ? "login-steps__item login-steps__item--done" : "login-steps__item"} />
          <li className={stepIndex >= 1 ? "login-steps__item login-steps__item--done" : "login-steps__item"} />
          <li className={stepIndex >= 2 ? "login-steps__item login-steps__item--done" : "login-steps__item"} />
        </ol>

        <input type="hidden" name="clientId" value={clientId} />
      <input type="hidden" name="redirectUri" value={redirectUri} />
      <input type="hidden" name="scope" value={scope} />
      <input type="hidden" name="state" value={state} />
      <input type="hidden" name="tenantOverride" value={tenantOverride ?? ""} />

      {(stepError || formState.error) && (
        <p role="alert" className="login-form__error">
          {stepError ?? formState.error}
        </p>
      )}

      {step === "username" && (
        <>
          <label className="login-form__field">
            Username
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="username"
              autoFocus
            />
          </label>
          <div className="login-form__buttons">
            <button
              type="button"
              onClick={() => {
                if (!email.trim()) {
                  setStepError("Enter your username.");
                  return;
                }
                setStepError(null);
                setStep("password");
              }}
            >
              Next
            </button>
          </div>
        </>
      )}

      {step === "password" && (
        <>
          <input type="hidden" name="email" value={email} />
          <p className="hint">{email}</p>
          <label className="login-form__field">
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
              autoFocus
            />
          </label>
          <div className="login-form__buttons">
            <button type="button" onClick={handlePasswordNext} disabled={checking}>
              {checking ? "Checking…" : "Next"}
            </button>
            <button
              type="button"
              className="login-form__button--secondary"
              disabled={checking}
              onClick={() => setStep("username")}
            >
              Back
            </button>
          </div>
        </>
      )}

      {step === "enroll" && (
        <>
          <input type="hidden" name="email" value={email} />
          <input type="hidden" name="password" value={password} />
          <p className="hint">{email}</p>
          <p>Scan this QR code with your authenticator app, then enter the 6-digit code it shows.</p>
          {qrDataUrl && (
            <div className="qr-wrap">
              <img src={qrDataUrl} alt="Authenticator QR code" width={180} height={180} />
            </div>
          )}

          <label className="login-form__field">
            Authenticator code
            <input
              type="text"
              name="totpCode"
              inputMode="numeric"
              pattern="\d{6}"
              maxLength={6}
              placeholder="123456"
              autoComplete="one-time-code"
              autoFocus
            />
          </label>

          <EnrollSubmitButtons onBack={() => setStep("password")} />
        </>
      )}

      {step === "code" && (
        <>
          <input type="hidden" name="email" value={email} />
          <input type="hidden" name="password" value={password} />
          <p className="hint">{email}</p>

          <label className="login-form__field">
            Authenticator code
            <input
              type="text"
              name="totpCode"
              inputMode="numeric"
              pattern="\d{6}"
              maxLength={6}
              placeholder="123456"
              autoComplete="one-time-code"
              autoFocus
            />
          </label>

          <SubmitButtons intent={intent} onIntentChange={setIntent} onBack={() => setStep("password")} />
        </>
      )}

      {step === "submitting-no-code" && (
        <>
          <input type="hidden" name="email" value={email} />
          <input type="hidden" name="password" value={password} />
          <input type="hidden" name="intent" value="none" />
          <p className="login-form__pending" aria-live="polite">
            Signing in…
          </p>
        </>
      )}
      </form>
    </>
  );
}

function EnrollSubmitButtons({ onBack }: { onBack: () => void }) {
  const { pending } = useFormStatus();

  if (pending) {
    return (
      <p className="login-form__pending" aria-live="polite">
        Verifying…
      </p>
    );
  }

  return (
    <div className="login-form__buttons">
      <button type="submit" name="intent" value="totp">
        Verify and sign in
      </button>
      <button type="button" className="login-form__button--secondary" onClick={onBack}>
        Back
      </button>
    </div>
  );
}

function SubmitButtons({
  intent,
  onIntentChange,
  onBack,
}: {
  intent: "totp" | "push";
  onIntentChange: (intent: "totp" | "push") => void;
  onBack: () => void;
}) {
  // useFormStatus only reports pending state for the <form> it's rendered
  // inside, per React's own rule -- this has to be a child component of the
  // <form>, not inlined in LoginForm itself.
  const { pending } = useFormStatus();

  if (pending) {
    return intent === "push" ? (
      <p className="login-form__pending" aria-live="polite">
        Check your phone for a sign-in request — this can take up to 60 seconds.
      </p>
    ) : (
      <p className="login-form__pending" aria-live="polite">
        Verifying…
      </p>
    );
  }

  return (
    <div className="login-form__buttons">
      <button type="submit" name="intent" value="totp" onClick={() => onIntentChange("totp")}>
        Sign in with code
      </button>
      <button
        type="submit"
        name="intent"
        value="push"
        className="login-form__button--secondary"
        onClick={() => onIntentChange("push")}
      >
        Send a push to my phone
      </button>
      <button type="button" className="login-form__button--secondary" onClick={onBack}>
        Back
      </button>
    </div>
  );
}
