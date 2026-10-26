import { useState } from "react";
import { loadSession, isImpersonating, endImpersonation } from "@/lib/session";

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
        onClick={() => {
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
