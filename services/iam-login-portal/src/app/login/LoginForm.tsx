"use client";

import { BrandHeader } from "../BrandHeader";
import { useActionState, useEffect, useRef, useState, type FormEvent } from "react";
import { useFormStatus } from "react-dom";
import QRCode from "qrcode";
import { earlyDeviceCheckAction, earlyIpCheckAction, issueDeviceChallengeAction, loginAction, precheckAction } from "./actions";
import { obtainDeviceProof, warmUpAgentPermission } from "@/lib/deviceProof";
import { enterAction, type LoginStep } from "@/lib/loginSteps";
import { initialLoginFormState } from "./types";

interface Props {
  /** True only when this organization has an app that requires a trusted device; false changes nothing about this page. */
  deviceSignIn?: boolean;
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  tenantOverride: string | null;
  tenantName: string;
  logoUrl?: string | null;
  headline?: string | null;
}

type Step = LoginStep;

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
export function LoginForm({ deviceSignIn = false, clientId, redirectUri, scope, state, tenantOverride, tenantName, logoUrl, headline }: Props) {
  const [formState, formAction] = useActionState(loginAction, initialLoginFormState);
  const [intent, setIntent] = useState<"totp" | "push">("totp");
  const [step, setStep] = useState<Step>("username");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [stepError, setStepError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  // The heads-up shown on the email screen when this laptop would not be allowed to sign in (see earlyDeviceCheckAction).
  const [deviceNotice, setDeviceNotice] = useState<string | null>(null);
  const [emailChecking, setEmailChecking] = useState(false);
  const formRef = useRef<HTMLFormElement>(null);
  const proofRef = useRef<HTMLInputElement>(null);
  // Device-bound sign-in bookkeeping (see onSubmitCapture). Refs, not state: they must not re-render anything.
  const preparingProof = useRef(false);
  const proofReady = useRef(false);
  const [preparing, setPreparing] = useState(false);
  // Started when the page loads (only for organizations that use device sign-in) so the browser's one-time
  // permission prompt is answered while the person types, not when they press Sign in.
  const warmUp = useRef<Promise<void> | null>(null);
  const warmUpDone = useRef(false);

  useEffect(() => {
    if (!deviceSignIn) return;
    warmUp.current = warmUpAgentPermission().then(() => {
      warmUpDone.current = true;
    });
  }, [deviceSignIn]);

  // mfaRequired=false: there's nothing left for the user to do, so submit
  // the real form the moment that step is reached, with no totpCode.
  useEffect(() => {
    if (step === "submitting-no-code") {
      formRef.current?.requestSubmit();
    }
  }, [step]);

  /**
   * Device-bound sign-in. Only does anything when this organization uses it (deviceSignIn). Just before the real
   * submit, asks the endpoint agent on this laptop to sign a fresh platform challenge, puts the result in the hidden
   * `deviceProof` field and then submits for real, with the same button the person pressed. A challenge is fetched this
   * late on purpose: it lives for two minutes, and the person may have spent a while typing their code.
   *
   * The whole thing is wrapped so it can only ever ADD a proof: no agent, a browser that blocks the local call, a
   * timeout, an error of any kind -- the form is submitted anyway, exactly as it would be without this feature.
   */
  function onSubmitCapture(event: FormEvent<HTMLFormElement>) {
    // Enter in the username or password box submits the form, but Next on those screens is not a submit button. Make Enter do
    // exactly what clicking Next does instead of firing the real sign-in half filled in (see lib/loginSteps.ts).
    const onEnter = enterAction(step);
    if (onEnter === "advance-username") {
      event.preventDefault();
      void goToPassword();
      return;
    }
    if (onEnter === "advance-password") {
      event.preventDefault();
      if (!checking) void handlePasswordNext();
      return;
    }
    if (!deviceSignIn || proofReady.current) {
      proofReady.current = false;
      return;
    }
    event.preventDefault();
    if (preparingProof.current) return; // a double click must not start a second attempt
    preparingProof.current = true;
    setPreparing(true);
    const form = event.currentTarget;
    const submitter = (event.nativeEvent as SubmitEvent).submitter as HTMLElement | null;
    // A prompt that is still unanswered gets more time; once it is answered (or there never was one) 4 s is plenty.
    const promptPending = warmUp.current !== null && !warmUpDone.current;
    void (async () => {
      try {
        const proof = await Promise.race([
          obtainDeviceProof({
            origin: window.location.origin,
            requestChallenge: () => issueDeviceChallengeAction(tenantOverride),
            waitFor: promptPending ? (warmUp.current ?? undefined) : undefined,
          }),
          new Promise<null>((resolve) => setTimeout(() => resolve(null), promptPending ? 22000 : 4000)),
        ]);
        if (proofRef.current) proofRef.current.value = proof ? JSON.stringify(proof) : "";
      } catch {
        if (proofRef.current) proofRef.current.value = "";
      } finally {
        proofReady.current = true;
        preparingProof.current = false;
        setPreparing(false);
        form.requestSubmit(submitter && submitter instanceof HTMLButtonElement ? submitter : undefined);
      }
    })();
  }

  /**
   * Asks the endpoint agent for a fresh signed proof for the password step, so the platform can tell this person right now
   * whether this laptop is allowed to sign in. Only ever adds a proof: no agent, a blocked local call or any error returns
   * nothing and the step carries on exactly as before. The final submit asks for its own proof (a challenge is single use).
   */
  async function proofForPasswordStep(): Promise<string | undefined> {
    if (!deviceSignIn) return undefined;
    const promptPending = warmUp.current !== null && !warmUpDone.current;
    try {
      const proof = await Promise.race([
        obtainDeviceProof({
          origin: window.location.origin,
          requestChallenge: () => issueDeviceChallengeAction(tenantOverride),
          waitFor: promptPending ? (warmUp.current ?? undefined) : undefined,
        }),
        new Promise<null>((resolve) => setTimeout(() => resolve(null), promptPending ? 22000 : 4000)),
      ]);
      return proof ? JSON.stringify(proof) : undefined;
    } catch {
      return undefined;
    }
  }

  function advanceToPassword() {
    setStepError(null);
    setDeviceNotice(null);
    setStep("password");
  }

  /**
   * Next on the email screen. When this organization uses device sign-in, first asks the platform whether THIS laptop would be
   * allowed in, so the person hears "you are not authorised to sign in from this device" right after typing the email instead
   * of after the password. Only the laptop's signed proof is sent, never the email. A refusal stops the person on this screen,
   * administrators included (owner's decision 2026-11-20: an administrator on an unauthorised laptop cannot use this portal from
   * it; the Admin Console sign-in is separate and unaffected). The check after the password is unchanged. Any failure of this
   * early check just moves on to the password screen as before.
   */
  async function goToPassword() {
    if (emailChecking) return;
    if (!email.trim()) {
      setStepError("Enter your username.");
      return;
    }
    setStepError(null);
    setDeviceNotice(null);
    setEmailChecking(true);
    try {
      // 1. Location and network rules: apply to everyone, administrators included, so a refusal stops the person right here.
      const ip = await earlyIpCheckAction(tenantOverride, email.trim());
      if (ip.notice) {
        setStepError(ip.notice);
        return;
      }
      // 2. Laptop rule: also stops the person here (see above).
      if (deviceSignIn) {
        const proof = await proofForPasswordStep();
        const { notice } = await earlyDeviceCheckAction(tenantOverride, proof);
        if (notice) {
          setDeviceNotice(notice);
          return;
        }
      }
      advanceToPassword();
    } catch {
      advanceToPassword();
    } finally {
      setEmailChecking(false);
    }
  }

  async function handlePasswordNext() {
    if (!password) {
      setStepError("Enter your password.");
      return;
    }
    setStepError(null);
    setChecking(true);
    try {
      const deviceProof = await proofForPasswordStep();
      const result = await precheckAction({ tenantOverride, email, password, deviceProof });
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
      <form ref={formRef} action={formAction} onSubmitCapture={onSubmitCapture} className="login-form">
        <h1>{headline || `Sign in to ${tenantName}`}</h1>
        <ol className="login-steps" aria-hidden="true">
          <li className={stepIndex >= 0 ? "login-steps__item login-steps__item--done" : "login-steps__item"} />
          <li className={stepIndex >= 1 ? "login-steps__item login-steps__item--done" : "login-steps__item"} />
          <li className={stepIndex >= 2 ? "login-steps__item login-steps__item--done" : "login-steps__item"} />
        </ol>

        <input type="hidden" name="deviceProof" ref={proofRef} defaultValue="" />
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
              onChange={(e) => {
                setEmail(e.target.value);
                setDeviceNotice(null);
              }}
              required
              autoComplete="username"
              autoFocus
            />
          </label>
          {deviceNotice && (
            <p role="alert" className="login-form__error">
              {deviceNotice}
            </p>
          )}
          <div className="login-form__buttons">
            <button type="button" onClick={() => void goToPassword()} disabled={emailChecking}>
              {emailChecking ? "Checking…" : "Next"}
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
              className="login-form__button--secondary login-form__button--back"
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

      {preparing && (
        <p className="login-form__pending" aria-live="polite">
          Checking this device…
        </p>
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
      <button type="button" className="login-form__button--secondary login-form__button--back" onClick={onBack}>
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
      <button type="button" className="login-form__button--secondary login-form__button--back" onClick={onBack}>
        Back
      </button>
    </div>
  );
}
