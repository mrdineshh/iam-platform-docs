import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import QRCode from "qrcode";
import { login, precheck } from "@/lib/auth";
import { findTenantBySubdomain, resolveTenantSubdomain } from "@/lib/tenant";
import { UpstreamError } from "@/lib/http";
import { saveSession } from "@/lib/session";
import { denialMessage } from "@/lib/errorCodes";
import { Typewriter } from "@/components/Typewriter";
import { detectRealIp } from "@/lib/clientIp";
import { applyBranding, type Branding } from "@/lib/branding";

type Step = "credentials" | "enroll" | "code";

export function LoginPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const tenantOverride = searchParams.get("tenant");

  const [step, setStep] = useState<Step>("credentials");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<"check" | "totp" | "push" | null>(null);
  const [sourceIp, setSourceIp] = useState<string | null>(null);
  const [brand, setBrand] = useState<{ name: string; branding: Branding | null } | null>(null);

  // Brand the page as soon as it opens (logo, color, headline), not only
  // after "Next": the tenant is known from the subdomain / ?tenant= already.
  useEffect(() => {
    const subdomain = resolveTenantSubdomain(window.location.hostname, tenantOverride);
    if (!subdomain) return;
    void findTenantBySubdomain(subdomain).then((tenant) => {
      if (!tenant) return;
      applyBranding(tenant.branding ?? null);
      setBrand({ name: tenant.name, branding: tenant.branding ?? null });
    });
  }, [tenantOverride]);

  async function resolveTenantOrFail() {
    const subdomain = resolveTenantSubdomain(window.location.hostname, tenantOverride);
    if (!subdomain) {
      setError("Could not determine which organization to sign in to.");
      return null;
    }
    const tenant = await findTenantBySubdomain(subdomain);
    if (!tenant) {
      setError("No organization was found for this sign-in link.");
      return null;
    }
    return tenant;
  }

  async function completeLogin(tenantId: string, tenantName: string, intent: "totp" | "push" | "none", ip: string) {
    setPending(intent === "none" ? "check" : intent);
    try {
      const result = await login({ tenantId, email, password, totpCode, sourceIp: ip }, intent);
      if (!result.token) {
        setError("Sign-in could not be completed. Please start again.");
        setStep("credentials");
        return;
      }
      saveSession({ token: result.token, role: result.role ?? "USER", tenantId, tenantName });
      navigate("/");
    } catch (err) {
      if (err instanceof UpstreamError) {
        if (err.status === 401) {
          setError("Incorrect email or password.");
        } else if (err.status === 403) {
          setError(denialMessage(err.errorCode, err.message));
        } else {
          setError("Sign-in is temporarily unavailable. Please try again.");
        }
      } else {
        setError("Sign-in is temporarily unavailable. Please try again.");
      }
      setStep("credentials");
    } finally {
      setPending(null);
    }
  }

  async function handleCredentialsNext() {
    setError(null);
    if (!email || !password) {
      setError("Enter your email and password.");
      return;
    }
    const tenant = await resolveTenantOrFail();
    if (!tenant) return;

    setPending("check");
    try {
      const ip = await detectRealIp();
      setSourceIp(ip);
      const result = await precheck({ tenantId: tenant.id, email, password, sourceIp: ip });
      if (!result.mfaRequired) {
        await completeLogin(tenant.id, tenant.name, "none", ip);
        return;
      }
      if (result.enrollmentRequired) {
        setQrDataUrl(result.provisioningUri ? await QRCode.toDataURL(result.provisioningUri) : null);
        setStep("enroll");
        return;
      }
      setStep("code");
    } catch (err) {
      if (err instanceof UpstreamError) {
        if (err.status === 401) {
          setError("Incorrect email or password.");
        } else if (err.status === 403) {
          setError(denialMessage(err.errorCode, err.message));
        } else {
          setError("Sign-in is temporarily unavailable. Please try again.");
        }
      } else {
        setError("Sign-in is temporarily unavailable. Please try again.");
      }
    } finally {
      setPending(null);
    }
  }

  async function submitCode(intent: "totp" | "push") {
    setError(null);
    if (intent === "totp" && !/^\d{6}$/.test(totpCode)) {
      setError("Enter the 6-digit code from your authenticator app.");
      return;
    }
    const tenant = await resolveTenantOrFail();
    if (!tenant) return;
    // Always set during the credentials step before either "enroll" or
    // "code" can be reached -- falls back to a fresh detection only if
    // that's somehow missing (e.g. a future caller skips straight here).
    const ip = sourceIp ?? (await detectRealIp());
    await completeLogin(tenant.id, tenant.name, intent, ip);
  }

  return (
    <main className="login-split">
      <aside className="login-split__art" aria-hidden="true">
        <img src="/login-art.jpg" alt="" />
        <div className="login-split__caption">
          <Typewriter lines={["One sign-in. Every app.", "Secure by policy, on every request."]} />
        </div>
      </aside>
      <section className="login-page login-split__panel">
      <div className="login-page__brand">
        {brand?.branding?.logoUrl ? (
          <img src={brand.branding.logoUrl} alt={brand.name} className="login-page__brand-logo" />
        ) : (
          <>
            <span className="login-page__brand-mark">{brand ? brand.name.charAt(0).toUpperCase() : "IAM"}</span>
            <span className="login-page__brand-name">{brand?.name ?? "Platform"}</span>
          </>
        )}
      </div>
      <form
        className="login-form"
        onSubmit={(e) => {
          e.preventDefault();
          if (step === "credentials") void handleCredentialsNext();
          else void submitCode("totp");
        }}
      >
        <h1>{brand?.branding?.headline ?? "Admin sign in"}</h1>
        <ol className="login-steps" aria-hidden="true">
          <li className="login-steps__item login-steps__item--done" />
          <li className={step !== "credentials" ? "login-steps__item login-steps__item--done" : "login-steps__item"} />
        </ol>

        {error && (
          <p role="alert" className="login-form__error">
            {error}
          </p>
        )}

        {step === "credentials" && (
          <>
            <label className="login-form__field">
              Email
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="username"
              />
            </label>

            <label className="login-form__field">
              Password
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="current-password"
              />
            </label>

            {pending === "check" ? (
              <p className="login-form__pending" aria-live="polite">
                Checking…
              </p>
            ) : (
              <div className="login-form__buttons">
                <button type="submit">Next</button>
              </div>
            )}
          </>
        )}

        {step === "enroll" && (
          <>
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
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                inputMode="numeric"
                pattern="\d{6}"
                maxLength={6}
                placeholder="123456"
                autoComplete="one-time-code"
                autoFocus
              />
            </label>

            {pending === "totp" ? (
              <p className="login-form__pending" aria-live="polite">
                Verifying…
              </p>
            ) : (
              <div className="login-form__buttons">
                <button type="submit">Verify and sign in</button>
                <button type="button" className="login-form__button--secondary" onClick={() => setStep("credentials")}>
                  Back
                </button>
              </div>
            )}
          </>
        )}

        {step === "code" && (
          <>
            <p className="hint">{email}</p>
            <label className="login-form__field">
              Authenticator code
              <input
                type="text"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                inputMode="numeric"
                pattern="\d{6}"
                maxLength={6}
                placeholder="123456"
                autoComplete="one-time-code"
                autoFocus
              />
            </label>

            {pending ? (
              <p className="login-form__pending" aria-live="polite">
                {pending === "push" ? "Check your phone for a sign-in request — this can take up to 60 seconds." : "Verifying…"}
              </p>
            ) : (
              <div className="login-form__buttons">
                <button type="submit">Sign in with code</button>
                <button type="button" className="login-form__button--secondary" onClick={() => void submitCode("push")}>
                  Send a push to my phone
                </button>
                <button type="button" className="login-form__button--secondary" onClick={() => setStep("credentials")}>
                  Back
                </button>
              </div>
            )}
          </>
        )}

        {step === "credentials" && (
          <p>
            <Link to="/onboard">Onboard a new organization</Link>
          </p>
        )}
      </form>
      </section>
    </main>
  );
}
