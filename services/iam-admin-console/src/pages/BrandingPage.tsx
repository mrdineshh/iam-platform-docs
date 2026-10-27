import { useEffect, useState } from "react";
import { getTenant } from "@/lib/tenant";
import { applyBranding, deriveColorTokens, EMPTY_BRANDING, updateBranding, type Branding } from "@/lib/branding";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import { Alert, PageHeader, PendingLabel, SkeletonRows } from "@/components/ui";
import { useConfirm, useToast } from "@/components/feedback";

const DEFAULT_COLOR = "#4f46e5";
const HEX = /^#[0-9a-fA-F]{6}$/;

/**
 * Self-service login-page branding (FR-6.1): color scheme, logo, headline and
 * default light/dark theme. Everything saved here is public (it is shown on
 * the pre-login page), and the page is only served on the tenant's own
 * subdomain (FR-6.2). Applied immediately to this console too, so the admin
 * sees exactly what their users will.
 */
export function BrandingPage() {
  const session = loadSession()!;
  const toast = useToast();
  const confirm = useConfirm();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const [useCustomColor, setUseCustomColor] = useState(false);
  const [color, setColor] = useState(DEFAULT_COLOR);
  const [logoUrl, setLogoUrl] = useState("");
  const [headline, setHeadline] = useState("");
  const [defaultTheme, setDefaultTheme] = useState<"" | "light" | "dark">("");
  const [logoFailed, setLogoFailed] = useState(false);

  function load(b: Branding | null | undefined) {
    const branding = b ?? EMPTY_BRANDING;
    setUseCustomColor(!!branding.primaryColor);
    setColor(branding.primaryColor ?? DEFAULT_COLOR);
    setLogoUrl(branding.logoUrl ?? "");
    setHeadline(branding.headline ?? "");
    setDefaultTheme(branding.defaultTheme ?? "");
  }

  useEffect(() => {
    (async () => {
      try {
        const tenant = await getTenant(session.tenantId);
        load(tenant.branding);
      } catch (err) {
        setError(errorMessage(err));
      } finally {
        setLoading(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => setLogoFailed(false), [logoUrl]);

  const colorValid = HEX.test(color);
  const logoValid = logoUrl.trim() === "" || /^https:\/\/\S+$/.test(logoUrl.trim());

  async function save(branding: Branding) {
    setSaving(true);
    setError(null);
    try {
      const saved = await updateBranding(session.tenantId, branding, session.token);
      applyBranding(saved);
      load(saved);
      toast.success("Branding saved.");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (useCustomColor && !colorValid) {
      setError("Enter the color as #RRGGBB, for example #4f46e5.");
      return;
    }
    if (!logoValid) {
      setError("The logo URL must start with https://");
      return;
    }
    await save({
      primaryColor: useCustomColor ? color.toLowerCase() : null,
      logoUrl: logoUrl.trim() || null,
      headline: headline.trim() || null,
      defaultTheme: defaultTheme || null,
    });
  }

  async function handleReset() {
    const ok = await confirm({
      title: "Reset branding?",
      message: "The sign-in page goes back to the default platform look. Your logo URL and headline are cleared.",
      confirmLabel: "Reset to default",
      danger: true,
    });
    if (ok) await save(EMPTY_BRANDING);
  }

  const previewVars = deriveColorTokens(useCustomColor && colorValid ? color : DEFAULT_COLOR) as React.CSSProperties;

  return (
    <main className="page">
      <PageHeader
        title="Branding"
        subtitle="Make the sign-in page look like your organization. Changes apply to your sign-in pages straight away."
      />

      {error && <Alert kind="error">{error}</Alert>}

      {loading ? (
        <SkeletonRows rows={4} />
      ) : (
        <div className="branding-layout">
          <form className="card card--padded" onSubmit={(e) => void handleSubmit(e)}>
            <h3 className="card__title">Appearance</h3>
            <p className="card__desc">Leave anything blank to keep the platform default for it.</p>

            <div className="branding-fields">
              <div className="login-form__field">
                Brand color
                <label className="checkbox-field">
                  <input type="checkbox" checked={useCustomColor} onChange={(e) => setUseCustomColor(e.target.checked)} />
                  Use a custom color
                </label>
                {useCustomColor && (
                  <div className="color-row">
                    <input
                      type="color"
                      className="color-row__picker"
                      value={colorValid ? color : DEFAULT_COLOR}
                      onChange={(e) => setColor(e.target.value)}
                      aria-label="Pick a brand color"
                    />
                    <input
                      value={color}
                      onChange={(e) => setColor(e.target.value)}
                      placeholder="#4f46e5"
                      maxLength={7}
                      aria-label="Brand color hex value"
                    />
                  </div>
                )}
              </div>

              <label className="login-form__field">
                Logo URL
                <input
                  value={logoUrl}
                  onChange={(e) => setLogoUrl(e.target.value)}
                  placeholder="https://example.com/logo.png"
                  inputMode="url"
                />
                <span className="field-hint">
                  {logoValid ? "A square or wide PNG, SVG or JPG hosted on https." : "Must start with https://"}
                </span>
              </label>

              <label className="login-form__field">
                Sign-in headline
                <input
                  value={headline}
                  onChange={(e) => setHeadline(e.target.value)}
                  placeholder={`Sign in to ${session.tenantName ?? "your organization"}`}
                  maxLength={120}
                />
              </label>

              <label className="login-form__field">
                Default theme
                <select value={defaultTheme} onChange={(e) => setDefaultTheme(e.target.value as "" | "light" | "dark")}>
                  <option value="">Follow each person's device</option>
                  <option value="light">Light</option>
                  <option value="dark">Dark</option>
                </select>
                <span className="field-hint">People can still switch themes themselves.</span>
              </label>
            </div>

            <div className="form-actions">
              <button type="button" className="btn-secondary" disabled={saving} onClick={() => void handleReset()}>
                Reset to default
              </button>
              <button type="submit" disabled={saving}>
                <PendingLabel pending={saving} idle="Save branding" busy="Saving…" />
              </button>
            </div>
          </form>

          <div>
            <p className="branding-preview__label">Preview</p>
            <div className="branding-preview" style={previewVars}>
              <div className="branding-preview__brand">
                {logoUrl.trim() && logoValid && !logoFailed ? (
                  <img src={logoUrl.trim()} alt="" className="branding-preview__logo" onError={() => setLogoFailed(true)} />
                ) : (
                  <span className="branding-preview__mark">{(session.tenantName ?? "IAM").charAt(0).toUpperCase()}</span>
                )}
                <span className="branding-preview__name">{session.tenantName ?? "Your organization"}</span>
              </div>
              <h4 className="branding-preview__headline">
                {headline.trim() || `Sign in to ${session.tenantName ?? "your organization"}`}
              </h4>
              <div className="branding-preview__input">Email</div>
              <div className="branding-preview__input">Password</div>
              <div className="branding-preview__button">Next</div>
            </div>
            {logoUrl.trim() && logoFailed && <p className="hint">The logo could not be loaded from that URL.</p>}
          </div>
        </div>
      )}
    </main>
  );
}

function errorMessage(err: unknown): string {
  if (err instanceof UpstreamError) {
    if (err.status === 400) return err.message || "Some of those values are not valid.";
    if (err.status === 401) return "Your session expired. Please sign in again.";
    if (err.status === 403) return "You don't have permission to do this.";
    return "This is temporarily unavailable. Please try again.";
  }
  return "This is temporarily unavailable. Please try again.";
}
