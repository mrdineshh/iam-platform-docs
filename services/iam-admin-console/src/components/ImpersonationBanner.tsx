import { useState } from "react";
import { loadSession, isImpersonating, endImpersonation } from "@/lib/session";
import { logout } from "@/lib/auth";

/** Shown on every page while an admin is "switched to" another user -- the one-click way back. */
export function ImpersonationBanner() {
  const [active, setActive] = useState(isImpersonating());
  const session = loadSession();

  if (!active || !session) return null;

  return (
    <div className="impersonation-banner">
      Viewing as <strong>{session.displayName ?? session.email ?? "this user"}</strong>
      <button
        type="button"
        onClick={async () => {
          // End the impersonated user's session instead of leaving it alive behind us.
          await logout(session.token);
          if (endImpersonation()) {
            setActive(false);
            window.location.href = "/";
          }
        }}
      >
        Switch back
      </button>
    </div>
  );
}
