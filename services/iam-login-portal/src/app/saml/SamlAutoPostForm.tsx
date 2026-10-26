"use client";

import { useEffect, useRef } from "react";

interface Props {
  acsUrl: string;
  samlResponse: string;
  relayState: string | null;
}

/**
 * SAML's HTTP-POST binding (SAML 2.0 Bindings 3.5) has to be a real
 * cross-origin form POST with a body -- there's no way to do that with an
 * HTTP redirect (which is why OIDC's equivalent step can just call
 * redirect() server-side, but this can't). Renders a hidden form and
 * submits it itself the moment it mounts; the visible fallback button
 * only matters if a browser blocks the auto-submit.
 */
export function SamlAutoPostForm({ acsUrl, samlResponse, relayState }: Props) {
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    formRef.current?.submit();
  }, []);

  return (
    <form ref={formRef} method="POST" action={acsUrl} className="login-form">
      <h1>Signing you in…</h1>
      <p className="hint">Redirecting back to the application. If nothing happens, click below.</p>
      <input type="hidden" name="SAMLResponse" value={samlResponse} />
      {relayState && <input type="hidden" name="RelayState" value={relayState} />}
      <div className="login-form__buttons">
        <button type="submit">Continue</button>
      </div>
    </form>
  );
}
