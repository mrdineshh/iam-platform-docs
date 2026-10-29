import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { createClient, type CreatedOidcClient } from "@/lib/oidcClients";
import { createSamlSp, getSamlIdpInfo, type SamlIdpInfo, type SamlSp } from "@/lib/samlSps";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import { config } from "@/lib/config";

type Tab = "general" | "integration";
type AppType = "OIDC" | "SAML";

/**
 * Setup wizard for connecting a third-party app -- we are always the
 * identity provider (AP-3), for both protocols. For OIDC this COLLECTS
 * what the app needs from us (name, redirect URIs, launch URL) and
 * GENERATES the Client ID/Secret. For SAML the relationship is the same
 * direction but the field shapes differ (an SP entity ID + ACS URL
 * instead of redirect URIs; no secret at all -- the SP trusts our signing
 * certificate instead), which is why "Application Type" branches the form
 * rather than sharing one field set.
 */
export function AppSetupPage() {
  const session = loadSession()!;
  const [searchParams] = useSearchParams();

  const [appType, setAppType] = useState<AppType>(searchParams.get("type") === "saml" ? "SAML" : "OIDC");
  const [tab, setTab] = useState<Tab>("general");
  const [name, setName] = useState(searchParams.get("name") ?? "");
  const [redirectUris, setRedirectUris] = useState<string[]>([""]);
  const [launchUrl, setLaunchUrl] = useState("");
  const [spEntityId, setSpEntityId] = useState("");
  const [acsUrl, setAcsUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [createdOidc, setCreatedOidc] = useState<CreatedOidcClient | null>(null);
  const [createdSaml, setCreatedSaml] = useState<SamlSp | null>(null);
  const [idpInfo, setIdpInfo] = useState<SamlIdpInfo | null>(null);
  const created = createdOidc ?? createdSaml;

  useEffect(() => {
    if (appType === "SAML" && !idpInfo) {
      void getSamlIdpInfo(session.token)
        .then(setIdpInfo)
        .catch(() => setError("Could not load this platform's SAML IdP details. Please try again."));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appType]);

  function updateRedirectUri(index: number, value: string) {
    setRedirectUris((prev) => prev.map((uri, i) => (i === index ? value : uri)));
  }

  function addRedirectUriField() {
    setRedirectUris((prev) => [...prev, ""]);
  }

  function removeRedirectUriField(index: number) {
    setRedirectUris((prev) => (prev.length > 1 ? prev.filter((_, i) => i !== index) : prev));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (appType === "OIDC") {
      const uris = redirectUris.map((uri) => uri.trim()).filter(Boolean);
      if (!name.trim() || uris.length === 0) {
        setError("Enter a name and at least one redirect URI.");
        return;
      }
      setSaving(true);
      try {
        const result = await createClient(session.tenantId, name.trim(), uris, session.token, launchUrl.trim());
        setCreatedOidc(result);
        setTab("integration");
      } catch (err) {
        setError(errorMessage(err));
      } finally {
        setSaving(false);
      }
      return;
    }

    if (!name.trim() || !spEntityId.trim() || !acsUrl.trim()) {
      setError("Enter a name, the SP's entity ID, and its ACS URL.");
      return;
    }
    setSaving(true);
    try {
      const result = await createSamlSp(session.tenantId, name.trim(), spEntityId.trim(), acsUrl.trim(), session.token, launchUrl.trim());
      setCreatedSaml(result);
      setTab("integration");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <main className="page">
      <h1>{name.trim() || "Connect an app"}</h1>

      {!created && (
        <div className="tabs">
          <button type="button" className={appType === "OIDC" ? "active" : ""} onClick={() => setAppType("OIDC")}>
            OpenID Connect
          </button>
          <button type="button" className={appType === "SAML" ? "active" : ""} onClick={() => setAppType("SAML")}>
            SAML
          </button>
        </div>
      )}
      {created && <span className="badge">{appType === "OIDC" ? "OpenID Connect" : "SAML"}</span>}

      {error && (
        <p role="alert" className="login-form__error">
          {error}
        </p>
      )}

      <div className="tabs">
        <button type="button" className={tab === "general" ? "active" : ""} onClick={() => setTab("general")}>
          General Details
        </button>
        <button
          type="button"
          className={tab === "integration" ? "active" : ""}
          onClick={() => created && setTab("integration")}
          disabled={!created}
        >
          Integration
        </button>
      </div>

      {tab === "general" && appType === "OIDC" && (
        <form className="setup-form" onSubmit={(e) => void handleSubmit(e)}>
          <label>
            App name
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. GitLab" required />
          </label>

          <label>
            Launch URL
            <input
              value={launchUrl}
              onChange={(e) => setLaunchUrl(e.target.value)}
              placeholder="https://app.example.com/sso/start (optional — shows a tile on My Apps)"
            />
          </label>

          <div>
            <label>Redirect URI(s)</label>
            {redirectUris.map((uri, i) => (
              <div className="setup-form__repeat-row" key={i}>
                <input
                  value={uri}
                  onChange={(e) => updateRedirectUri(i, e.target.value)}
                  placeholder="https://app.example.com/auth/callback"
                />
                <button type="button" className="btn-secondary" onClick={() => removeRedirectUriField(i)} disabled={redirectUris.length === 1}>
                  &minus;
                </button>
              </div>
            ))}
            <button type="button" className="btn-secondary" onClick={addRedirectUriField}>
              + Add another redirect URI
            </button>
          </div>

          <button type="submit" disabled={saving || !!created}>
            {saving ? "Connecting…" : created ? "Connected" : "Connect app"}
          </button>
        </form>
      )}

      {tab === "general" && appType === "SAML" && (
        <form className="setup-form" onSubmit={(e) => void handleSubmit(e)}>
          <p className="hint">
            Google Workspace: Admin console → Security → Authentication → SSO with third party IdP. Use the values
            below in this form, then copy this platform's IdP details (shown after connecting) into that Google
            page.
          </p>

          <label>
            App name
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Google Workspace" required />
          </label>

          <label>
            SP entity ID
            <input
              value={spEntityId}
              onChange={(e) => setSpEntityId(e.target.value)}
              placeholder="e.g. google.com"
              required
            />
          </label>

          <label>
            ACS URL
            <input
              value={acsUrl}
              onChange={(e) => setAcsUrl(e.target.value)}
              placeholder="The Assertion Consumer Service URL Google gives you on that setup page"
              required
            />
          </label>

          <label>
            Launch URL
            <input
              value={launchUrl}
              onChange={(e) => setLaunchUrl(e.target.value)}
              placeholder="https://mail.google.com/a/yourdomain.com (optional — shows a tile on My Apps)"
            />
          </label>

          <button type="submit" disabled={saving || !!created}>
            {saving ? "Connecting…" : created ? "Connected" : "Connect app"}
          </button>
        </form>
      )}

      {tab === "integration" && createdOidc && (
        <div className="callout">
          <p>
            <strong>{createdOidc.name}</strong> is connected. Copy these into that app&apos;s own OIDC/SSO settings
            &mdash; the secret is shown only this once.
          </p>
          <p>
            Client ID
            <code>{createdOidc.clientId}</code>
          </p>
          <p>
            Client secret
            <code>{createdOidc.clientSecret}</code>
          </p>
          <p>
            Issuer / discovery
            <code>{config.oidcIssuerUrl}/.well-known/openid-configuration</code>
          </p>
        </div>
      )}

      {tab === "integration" && createdSaml && idpInfo && (
        <div className="callout">
          <p>
            <strong>{createdSaml.name}</strong> is connected. Paste these into that SP&apos;s own SAML SSO settings
            (for Google Workspace: Security → Authentication → SSO with third party IdP).
          </p>
          <p>
            IdP entity ID
            <code>{idpInfo.entityId}</code>
          </p>
          <p>
            Sign-in page URL (SSO URL)
            <code>{idpInfo.ssoUrl}</code>
          </p>
          <p>
            Signing certificate
            <code>{idpInfo.certificatePem}</code>
          </p>
        </div>
      )}

      {created && (
        <p>
          <Link to="/clients">Done &mdash; back to Applications</Link>
        </p>
      )}
    </main>
  );
}

function errorMessage(err: unknown): string {
  if (err instanceof UpstreamError) {
    if (err.status === 401) return "Your session expired. Please sign in again.";
    if (err.status === 403) return "You don't have permission to do this.";
    if (err.status === 409) return "An app with that entity ID is already registered.";
    return "This is temporarily unavailable. Please try again.";
  }
  return "This is temporarily unavailable. Please try again.";
}
