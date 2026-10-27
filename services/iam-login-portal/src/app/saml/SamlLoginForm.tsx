"use client";

import { BrandHeader } from "../BrandHeader";
import { useActionState, useEffect, useRef, useState } from "react";
import { useFormStatus } from "react-dom";
import QRCode from "qrcode";
import { precheckAction } from "../login/actions";
import { samlLoginAction } from "./actions";
import { initialSamlLoginFormState } from "./types";
import { SamlAutoPostForm } from "./SamlAutoPostForm";

interface Props {
  samlRequestId: string;
  tenantOverride: string | null;
  tenantName: string;
  logoUrl?: string | null;
  headline?: string | null;
}

type Step = "username" | "password" | "enroll" | "code" | "submitting-no-code";

/**
 * SAML counterpart to ../login/LoginForm.tsx -- same wizard (username ->
 * password -> [enroll QR | code]), same precheckAction (protocol-agnostic
 * already: it only needs tenant/email/password), different only in how it
 * finishes: on success this renders SamlAutoPostForm instead of the OIDC
 * flow's server-side redirect(), since HTTP-POST binding needs a real
 * client-side form submit. There's no "mfaRequired=false, submit
 * immediately" step here the way the OIDC form has one -- useActionState's
 * result (formState.autoPost) already covers that case identically to the
 * code path, so a single extra screen isn't needed.
 */
export function SamlLoginForm({ samlRequestId, tenantOverride, tenantName, logoUrl, headline }: Props) {
  const [formState, formAction] = useActionState(samlLoginAction, initialSamlLoginFormState);
  const [intent, setIntent] = useState<"totp" | "push">("totp");
  const [step, setStep] = useState<Step>("username");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [stepError, setStepError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const formRef = useRef<HTMLFormElement>(null);

  // mfaRequired=false: nothing left for the user to do, submit the real
  // form the moment that step is reached, with no totpCode -- same pattern
  // as the OIDC form's "submitting-no-code" step.
  useEffect(() => {
    if (step === "submitting-no-code") {
      formRef.current?.requestSubmit();
    }
  }, [step]);

  if (formState.autoPost) {
    return (
      <SamlAutoPostForm
        acsUrl={formState.autoPost.acsUrl}
        samlResponse={formState.autoPost.samlResponse}
        relayState={formState.autoPost.relayState}
      />
    );
  }

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
      <BrandHeader tenantName={tenantName} logoUrl={logoUrl} />
      <form ref={formRef} action={formAction} className="login-form">
        <h1>{headline || `Sign in to ${tenantName}`}</h1>
        <ol className="login-steps" aria-hidden="true">
          <li className={stepIndex >= 0 ? "login-steps__item login-steps__item--done" : "login-steps__item"} />
          <li className={stepIndex >= 1 ? "login-steps__item login-steps__item--done" : "login-steps__item"} />
          <li className={stepIndex >= 2 ? "login-steps__item login-steps__item--done" : "login-steps__item"} />
        </ol>

        <input type="hidden" name="samlRequestId" value={samlRequestId} />
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
