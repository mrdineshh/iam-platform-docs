import { useEffect, useState } from "react";
import { listMyApps, type MyAppTile } from "@/lib/myApps";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import { config } from "@/lib/config";

/**
 * "Click the app icon, you're in" -- lists every app this user is allowed
 * to launch, as a clickable tile. Backed by iam-tenant-svc's /my-apps
 * (group-filtered: an ADMIN sees every connected app with a launchUrl, a
 * regular user only sees apps assigned to their own group -- see
 * MyAppsController's doc comment). Any logged-in user sees this page; the
 * filtering happens server-side, not here.
 *
 * The SSO piece that makes clicking a tile skip login entirely lives in
 * iam-login-portal's httpOnly cookie -- but this SPA has no server to set
 * one itself. Each tile is a POST form to iam-login-portal's
 * /sso-handoff, which sets that cookie from this session's own token and
 * then forwards the browser into launchUrl -- without it, a user who
 * signed in here (rather than iam-login-portal's own /portal) would
 * always be re-prompted the first time they open an app.
 */
export function LaunchpadPage() {
  const session = loadSession()!;
  const [apps, setApps] = useState<MyAppTile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      setLoading(true);
      setError(null);
      try {
        setApps(await listMyApps(session.tenantId, session.token));
      } catch (err) {
        setError(errorMessage(err));
      } finally {
        setLoading(false);
      }
      // eslint-disable-next-line react-hooks/exhaustive-deps
    })();
  }, []);

  return (
    <main className="page">
      <h1>My Apps</h1>

      {error && (
        <p role="alert" className="login-form__error">
          {error}
        </p>
      )}

      {loading ? (
        <p>Loading…</p>
      ) : apps.length === 0 ? (
        <p>
          No apps are set up to launch from here yet. An admin can add a "Launch URL" when connecting an app on the
          Applications page.
        </p>
      ) : (
        <div className="app-tiles">
          {apps.map((app) => (
            <form
              key={app.id}
              method="POST"
              action={`${config.loginPortalUrl}/sso-handoff`}
              target="_blank"
              className="app-tile-form"
            >
              <input type="hidden" name="token" value={session.token} />
              <input type="hidden" name="next" value={app.launchUrl} />
              <button type="submit" className="app-tile">
                <span className="app-tile__icon" aria-hidden="true">
                  {app.name.charAt(0).toUpperCase()}
                </span>
                <span className="app-tile__name">{app.name}</span>
              </button>
            </form>
          ))}
        </div>
      )}
    </main>
  );
}

function errorMessage(err: unknown): string {
  if (err instanceof UpstreamError) {
    if (err.status === 401) return "Your session expired. Please sign in again.";
    return "This is temporarily unavailable. Please try again.";
  }
  return "This is temporarily unavailable. Please try again.";
}
