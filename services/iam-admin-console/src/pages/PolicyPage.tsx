import { useEffect, useState } from "react";
import { getPolicy, putPolicy } from "@/lib/policy";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";

export function PolicyPage() {
  const session = loadSession()!;
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [allowedCountries, setAllowedCountries] = useState("");
  const [allowedHardCap, setAllowedHardCap] = useState(false);
  const [blockedCountries, setBlockedCountries] = useState("");
  const [blockedHardCap, setBlockedHardCap] = useState(false);
  const [reenrollEveryLogin, setReenrollEveryLogin] = useState(false);
  const [reenrollHardCap, setReenrollHardCap] = useState(false);

  useEffect(() => {
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const policy = await getPolicy(session.tenantId, "TENANT", undefined, session.token);
        if (policy) {
          setAllowedCountries((policy.allowedCountries ?? []).join(", "));
          setAllowedHardCap(policy.allowedCountriesHardCap);
          setBlockedCountries((policy.blockedCountries ?? []).join(", "));
          setBlockedHardCap(policy.blockedCountriesHardCap);
          setReenrollEveryLogin(policy.totpReenrollEveryLogin ?? false);
          setReenrollHardCap(policy.totpReenrollEveryLoginHardCap);
        }
        // No policy stored yet at TENANT scope is a normal state (fresh
        // tenant) -- the form just starts empty, not an error.
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
    setSaved(false);
    try {
      await putPolicy(
        {
          tenantId: session.tenantId,
          scope: "TENANT",
          allowedCountries: toList(allowedCountries),
          allowedCountriesHardCap: allowedHardCap,
          blockedCountries: toList(blockedCountries),
          blockedCountriesHardCap: blockedHardCap,
          totpReenrollEveryLogin: reenrollEveryLogin,
          totpReenrollEveryLoginHardCap: reenrollHardCap,
        },
        session.token,
      );
      setSaved(true);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  if (loading) {
    return (
      <main className="page">
        <p>Loading…</p>
      </main>
    );
  }

  return (
    <main className="page">
      <h1>Access policy — tenant-wide</h1>
      <p className="hint">
        Applies to every user in this tenant unless a more specific OU/user-level policy overrides it (unless a field
        here is marked as a hard cap, in which case nothing more specific can override it).
      </p>

      {error && (
        <p role="alert" className="login-form__error">
          {error}
        </p>
      )}
      {saved && <p className="callout">Saved.</p>}

      <form className="policy-form" onSubmit={(e) => void handleSave(e)}>
        <label className="login-form__field">
          Allowed countries (ISO 3166-1 alpha-2, comma-separated — leave blank to allow all)
          <input value={allowedCountries} onChange={(e) => setAllowedCountries(e.target.value)} placeholder="US, CA, GB" />
        </label>
        <label className="checkbox-field">
          <input type="checkbox" checked={allowedHardCap} onChange={(e) => setAllowedHardCap(e.target.checked)} />
          Hard cap (no OU/user policy can override this)
        </label>

        <label className="login-form__field">
          Blocked countries (comma-separated)
          <input value={blockedCountries} onChange={(e) => setBlockedCountries(e.target.value)} placeholder="KP, RU" />
        </label>
        <label className="checkbox-field">
          <input type="checkbox" checked={blockedHardCap} onChange={(e) => setBlockedHardCap(e.target.checked)} />
          Hard cap (no OU/user policy can override this)
        </label>

        <label className="checkbox-field">
          <input
            type="checkbox"
            checked={reenrollEveryLogin}
            onChange={(e) => setReenrollEveryLogin(e.target.checked)}
          />
          Require a brand-new authenticator QR code every login (instead of reusing the same enrolled device)
        </label>
        <label className="checkbox-field">
          <input type="checkbox" checked={reenrollHardCap} onChange={(e) => setReenrollHardCap(e.target.checked)} />
          Hard cap (no OU/user policy can override this)
        </label>

        <button type="submit">Save policy</button>
      </form>
    </main>
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
    if (err.status === 401) return "Your session expired. Please sign in again.";
    if (err.status === 403) return "You don't have permission to do this.";
    return "This is temporarily unavailable. Please try again.";
  }
  return "This is temporarily unavailable. Please try again.";
}
