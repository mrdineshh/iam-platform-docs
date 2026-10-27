import { useEffect, useState, type ReactNode } from "react";
import {
  DEFAULT_LOCKOUT_MINUTES,
  DEFAULT_MIN_PASSWORD_LENGTH,
  getPolicy,
  putPolicy,
  type Policy,
} from "@/lib/policy";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import { Alert, PageHeader, PendingLabel, SkeletonRows } from "@/components/ui";
import { useToast } from "@/components/feedback";

type TriState = "" | "true" | "false";

/**
 * Tenant-wide access policy. One PUT carries every tenant-scope attribute --
 * iam-policy-svc overwrites the whole row, so anything this page didn't send
 * (tenant IP ranges, the 2FA requirement) would be wiped on save. Hence every
 * field the engine stores at TENANT scope is loaded here and sent back.
 */
export function PolicyPage() {
  const session = loadSession()!;
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Sign-in location
  const [allowedCountries, setAllowedCountries] = useState("");
  const [allowedCountriesHardCap, setAllowedCountriesHardCap] = useState(false);
  const [blockedCountries, setBlockedCountries] = useState("");
  const [blockedCountriesHardCap, setBlockedCountriesHardCap] = useState(false);
  const [allowedCidrs, setAllowedCidrs] = useState("");
  const [allowedCidrsHardCap, setAllowedCidrsHardCap] = useState(false);
  const [blockedCidrs, setBlockedCidrs] = useState("");
  const [blockedCidrsHardCap, setBlockedCidrsHardCap] = useState(false);

  // Two-factor
  const [mfaRequired, setMfaRequired] = useState<TriState>("");
  const [mfaHardCap, setMfaHardCap] = useState(false);
  const [reenrollEveryLogin, setReenrollEveryLogin] = useState(false);
  const [reenrollHardCap, setReenrollHardCap] = useState(false);

  // Password rules (FR-3.1)
  const [minLength, setMinLength] = useState(String(DEFAULT_MIN_PASSWORD_LENGTH));
  const [requireUpper, setRequireUpper] = useState(false);
  const [requireLower, setRequireLower] = useState(false);
  const [requireDigit, setRequireDigit] = useState(false);
  const [requireSymbol, setRequireSymbol] = useState(false);

  // Account lockout (FR-3.5)
  const [lockoutEnabled, setLockoutEnabled] = useState(false);
  const [lockoutThreshold, setLockoutThreshold] = useState("5");
  const [lockoutPermanent, setLockoutPermanent] = useState(false);
  const [lockoutMinutes, setLockoutMinutes] = useState(String(DEFAULT_LOCKOUT_MINUTES));

  function load(p: Policy) {
    setAllowedCountries((p.allowedCountries ?? []).join(", "));
    setAllowedCountriesHardCap(p.allowedCountriesHardCap);
    setBlockedCountries((p.blockedCountries ?? []).join(", "));
    setBlockedCountriesHardCap(p.blockedCountriesHardCap);
    setAllowedCidrs((p.allowedCidrs ?? []).join(", "));
    setAllowedCidrsHardCap(p.allowedCidrsHardCap);
    setBlockedCidrs((p.blockedCidrs ?? []).join(", "));
    setBlockedCidrsHardCap(p.blockedCidrsHardCap);
    setMfaRequired(p.mfaRequired === null ? "" : p.mfaRequired ? "true" : "false");
    setMfaHardCap(p.mfaRequiredHardCap);
    setReenrollEveryLogin(p.totpReenrollEveryLogin ?? false);
    setReenrollHardCap(p.totpReenrollEveryLoginHardCap);
    setMinLength(String(p.passwordMinLength ?? DEFAULT_MIN_PASSWORD_LENGTH));
    setRequireUpper(p.passwordRequireUppercase ?? false);
    setRequireLower(p.passwordRequireLowercase ?? false);
    setRequireDigit(p.passwordRequireDigit ?? false);
    setRequireSymbol(p.passwordRequireSymbol ?? false);
    const threshold = p.lockoutThreshold ?? 0;
    setLockoutEnabled(threshold > 0);
    setLockoutThreshold(String(threshold > 0 ? threshold : 5));
    setLockoutPermanent(p.lockoutPermanent ?? false);
    setLockoutMinutes(String(p.lockoutDurationMinutes ?? DEFAULT_LOCKOUT_MINUTES));
  }

  useEffect(() => {
    (async () => {
      try {
        // No policy stored yet at TENANT scope is a normal state (fresh
        // tenant): the form just starts at the platform defaults.
        const policy = await getPolicy(session.tenantId, "TENANT", undefined, session.token);
        if (policy) load(policy);
      } catch (err) {
        setError(errorMessage(err));
      } finally {
        setLoading(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    const minLen = Number(minLength);
    if (!Number.isInteger(minLen) || minLen < 8 || minLen > 128) {
      setError("Minimum password length must be a whole number from 8 to 128.");
      return;
    }
    const threshold = Number(lockoutThreshold);
    const minutes = Number(lockoutMinutes);
    if (lockoutEnabled) {
      if (!Number.isInteger(threshold) || threshold < 1 || threshold > 100) {
        setError("Failed attempts before lockout must be a whole number from 1 to 100.");
        return;
      }
      if (!lockoutPermanent && (!Number.isInteger(minutes) || minutes < 1 || minutes > 10080)) {
        setError("Lockout duration must be a whole number of minutes from 1 to 10080 (one week).");
        return;
      }
    }

    setSaving(true);
    try {
      const saved = await putPolicy(
        {
          tenantId: session.tenantId,
          scope: "TENANT",
          allowedCountries: toList(allowedCountries),
          allowedCountriesHardCap,
          blockedCountries: toList(blockedCountries),
          blockedCountriesHardCap,
          allowedCidrs: toList(allowedCidrs),
          allowedCidrsHardCap,
          blockedCidrs: toList(blockedCidrs),
          blockedCidrsHardCap,
          mfaRequired: mfaRequired === "" ? null : mfaRequired === "true",
          mfaRequiredHardCap: mfaHardCap,
          totpReenrollEveryLogin: reenrollEveryLogin,
          totpReenrollEveryLoginHardCap: reenrollHardCap,
          passwordMinLength: minLen,
          passwordRequireUppercase: requireUpper,
          passwordRequireLowercase: requireLower,
          passwordRequireDigit: requireDigit,
          passwordRequireSymbol: requireSymbol,
          lockoutThreshold: lockoutEnabled ? threshold : null,
          lockoutDurationMinutes: lockoutEnabled && !lockoutPermanent ? minutes : null,
          lockoutPermanent: lockoutEnabled ? lockoutPermanent : null,
        },
        session.token,
      );
      load(saved);
      toast.success("Access policy saved.");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <main className="page page--narrow">
      <PageHeader
        title="Access policy"
        subtitle="Tenant-wide sign-in rules. They apply to everyone unless a group or user overrides them, except settings marked as a hard cap, which nothing more specific can override."
      />

      {error && <Alert kind="error">{error}</Alert>}

      {loading ? (
        <SkeletonRows rows={5} />
      ) : (
        <form onSubmit={(e) => void handleSave(e)}>
          <Section title="Sign-in location" description="Where people are allowed to sign in from.">
            <div className="form-grid">
              <Field
                id="allowed-countries"
                label="Allowed countries"
                hint="ISO country codes, comma-separated. Blank allows all."
                hardCap={{ checked: allowedCountriesHardCap, onChange: setAllowedCountriesHardCap }}
              >
                <input id="allowed-countries" value={allowedCountries} onChange={(e) => setAllowedCountries(e.target.value)} placeholder="US, CA, GB" />
              </Field>
              <Field
                id="blocked-countries"
                label="Blocked countries"
                hint="Always denied, even if the country is also allowed."
                hardCap={{ checked: blockedCountriesHardCap, onChange: setBlockedCountriesHardCap }}
              >
                <input id="blocked-countries" value={blockedCountries} onChange={(e) => setBlockedCountries(e.target.value)} placeholder="KP, RU" />
              </Field>
              <Field
                id="allowed-cidrs"
                label="Allowed IP ranges"
                hint="CIDR ranges, comma-separated. Blank allows any IP."
                hardCap={{ checked: allowedCidrsHardCap, onChange: setAllowedCidrsHardCap }}
              >
                <input id="allowed-cidrs" value={allowedCidrs} onChange={(e) => setAllowedCidrs(e.target.value)} placeholder="203.0.113.0/24" />
              </Field>
              <Field
                id="blocked-cidrs"
                label="Blocked IP ranges"
                hint="CIDR ranges, comma-separated."
                hardCap={{ checked: blockedCidrsHardCap, onChange: setBlockedCidrsHardCap }}
              >
                <input id="blocked-cidrs" value={blockedCidrs} onChange={(e) => setBlockedCidrs(e.target.value)} placeholder="198.51.100.0/24" />
              </Field>
            </div>
          </Section>

          <Section title="Two-factor authentication" description="The second step after the password.">
            <div className="form-grid">
              <Field id="mfa-required" label="Require 2FA" hardCap={{ checked: mfaHardCap, onChange: setMfaHardCap }}>
                <select id="mfa-required" value={mfaRequired} onChange={(e) => setMfaRequired(e.target.value as TriState)}>
                  <option value="">Default (required)</option>
                  <option value="true">Required</option>
                  <option value="false">Not required (password only)</option>
                </select>
              </Field>
            </div>
            <ToggleRow
              title="New authenticator code every sign-in"
              description="Issue a fresh QR code at every sign-in instead of reusing the enrolled device."
              checked={reenrollEveryLogin}
              onChange={setReenrollEveryLogin}
              hardCap={{ checked: reenrollHardCap, onChange: setReenrollHardCap }}
            />
          </Section>

          <Section
            title="Password rules"
            description="Checked whenever an administrator creates a user or sets a password. Existing passwords are not re-checked."
          >
            <div className="form-grid">
              <label className="login-form__field">
                Minimum length
                <input
                  type="number"
                  min={8}
                  max={128}
                  value={minLength}
                  onChange={(e) => setMinLength(e.target.value)}
                />
                <span className="field-hint">From 8 to 128 characters.</span>
              </label>
            </div>
            <ToggleRow title="Require an uppercase letter" checked={requireUpper} onChange={setRequireUpper} />
            <ToggleRow title="Require a lowercase letter" checked={requireLower} onChange={setRequireLower} />
            <ToggleRow title="Require a number" checked={requireDigit} onChange={setRequireDigit} />
            <ToggleRow title="Require a symbol" checked={requireSymbol} onChange={setRequireSymbol} />
          </Section>

          <Section
            title="Account lockout"
            description="Lock an account after repeated wrong passwords, to stop password guessing."
          >
            <ToggleRow
              title="Lock accounts after failed sign-ins"
              description="Off by default. A correct password clears the count."
              checked={lockoutEnabled}
              onChange={setLockoutEnabled}
            />
            {lockoutEnabled && (
              <>
                <div className="form-grid" style={{ marginTop: 12 }}>
                  <label className="login-form__field">
                    Failed attempts before lockout
                    <input
                      type="number"
                      min={1}
                      max={100}
                      value={lockoutThreshold}
                      onChange={(e) => setLockoutThreshold(e.target.value)}
                    />
                  </label>
                  {!lockoutPermanent && (
                    <label className="login-form__field">
                      Lock for (minutes)
                      <input
                        type="number"
                        min={1}
                        max={10080}
                        value={lockoutMinutes}
                        onChange={(e) => setLockoutMinutes(e.target.value)}
                      />
                    </label>
                  )}
                </div>
                <ToggleRow
                  title="Stay locked until an administrator unlocks the account"
                  description="Instead of unlocking by itself after the time above. Unlock from the Users page."
                  checked={lockoutPermanent}
                  onChange={setLockoutPermanent}
                />
              </>
            )}
          </Section>

          <div className="form-actions" style={{ borderTop: "none" }}>
            <button type="submit" disabled={saving}>
              <PendingLabel pending={saving} idle="Save policy" busy="Saving…" />
            </button>
          </div>
        </form>
      )}
    </main>
  );
}

function Section({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return (
    <section className="card card--padded" style={{ marginBottom: 20 }}>
      <h3 className="card__title">{title}</h3>
      <p className="card__desc">{description}</p>
      {children}
    </section>
  );
}

function Field({
  id,
  label,
  hint,
  hardCap,
  children,
}: {
  id: string;
  label: string;
  hint?: string;
  hardCap?: { checked: boolean; onChange: (v: boolean) => void };
  children: ReactNode;
}) {
  return (
    <div className="login-form__field">
      <label htmlFor={id}>{label}</label>
      {children}
      {hint && <span className="field-hint">{hint}</span>}
      {hardCap && <HardCap checked={hardCap.checked} onChange={hardCap.onChange} />}
    </div>
  );
}

function HardCap({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="checkbox-field" style={{ marginTop: 4 }}>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span className="field-hint">Hard cap: groups and users cannot override this</span>
    </label>
  );
}

function ToggleRow({
  title,
  description,
  checked,
  onChange,
  hardCap,
}: {
  title: string;
  description?: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  hardCap?: { checked: boolean; onChange: (v: boolean) => void };
}) {
  return (
    <div className="toggle-row">
      <div>
        <div className="toggle-row__title">{title}</div>
        {description && <p className="toggle-row__desc">{description}</p>}
        {hardCap && <HardCap checked={hardCap.checked} onChange={hardCap.onChange} />}
      </div>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} aria-label={title} />
    </div>
  );
}

function toList(value: string): string[] | null {
  const items = value
    .split(",")
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
  return items.length > 0 ? items : null;
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
