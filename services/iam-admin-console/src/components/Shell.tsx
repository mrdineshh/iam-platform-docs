import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { clearSession, isAdmin, loadImpersonationOriginal, loadSession } from "@/lib/session";
import { logout } from "@/lib/auth";
import { useIdleTimeout } from "@/lib/useIdleTimeout";
import { ThemeToggle } from "@/components/ThemeToggle";
import { loadStoredBranding } from "@/lib/branding";
import { Icon, type IconName } from "@/components/icons";
import { BackLink } from "@/components/ui";

// Where the "back" link on each page leads. The dashboard is the top level, so it has none.
const BACK_TARGETS: Record<string, { to: string; label: string }> = {
  "/apps": { to: "/", label: "Dashboard" },
  "/my-security": { to: "/", label: "Dashboard" },
  "/users": { to: "/", label: "Dashboard" },
  "/groups": { to: "/", label: "Dashboard" },
  "/switch-user": { to: "/", label: "Dashboard" },
  "/clients": { to: "/", label: "Dashboard" },
  "/policy": { to: "/", label: "Dashboard" },
  "/branding": { to: "/", label: "Dashboard" },
  "/clients/setup": { to: "/clients", label: "Applications" },
  "/google-workspace": { to: "/clients", label: "Applications" },
};

const SIDEBAR_COLLAPSED_KEY = "iam-admin-console:sidebar-collapsed";
const ADMIN_SECTION_OPEN_KEY = "iam-admin-console:admin-nav-open";
// Signs the person out after this long with no activity in the tab.
const IDLE_SIGN_OUT_MS = 30 * 60 * 1000;

/**
 * Persistent sidebar + topbar wrapped around every authenticated page
 * (mounted once, inside ProtectedRoute/SessionRoute -- not per-page) so
 * navigation, the signed-in identity, and sign-out live in exactly one
 * place instead of each page re-implementing its own "<- Dashboard" link.
 *
 * Sidebar collapse and the Administration section's open/closed state
 * both persist in localStorage so they survive a reload -- not just
 * component state, since a collapsed sidebar that snaps back open on
 * every navigation would be worse than not collapsible at all.
 */
export function Shell({ children }: { children: ReactNode }) {
  const session = loadSession();
  const location = useLocation();
  const navigate = useNavigate();
  const admin = isAdmin(session);

  const [collapsed, setCollapsed] = useState(() => localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === "1");
  const [adminOpen, setAdminOpen] = useState(() => {
    const stored = localStorage.getItem(ADMIN_SECTION_OPEN_KEY);
    // Default open the first time so admins discover the section at all;
    // after that, respect whatever they left it as.
    return stored === null ? true : stored === "1";
  });

  useEffect(() => {
    localStorage.setItem(SIDEBAR_COLLAPSED_KEY, collapsed ? "1" : "0");
  }, [collapsed]);

  useEffect(() => {
    localStorage.setItem(ADMIN_SECTION_OPEN_KEY, adminOpen ? "1" : "0");
  }, [adminOpen]);

  // A tab left open on a shared or unattended computer must not stay usable.
  const idleSignOut = useRef<() => void>(() => undefined);
  idleSignOut.current = () => void handleSignOut("idle");
  useIdleTimeout(useCallback(() => idleSignOut.current(), []), IDLE_SIGN_OUT_MS);

  // Ends the session(s) on the server first so the sign-out is real and audited,
  // not just forgotten by this browser. Includes the admin's own session if they
  // are currently "switched to" another user.
  async function handleSignOut(reason?: "idle") {
    const original = loadImpersonationOriginal();
    await Promise.all([session ? logout(session.token) : undefined, original ? logout(original.token) : undefined]);
    clearSession();
    navigate(reason === "idle" ? "/login?reason=idle" : "/login");
  }

  const back = BACK_TARGETS[location.pathname.replace(/\/+$/, "") || "/"];
  const backBar = back ? (
    <div className="shell__back">
      <BackLink to={back.to}>{back.label}</BackLink>
    </div>
  ) : null;

  const branding = loadStoredBranding();
  const identityLabel = session?.email ?? session?.tenantName ?? "Signed in";
  const adminIsCurrentSection =
    location.pathname === "/users" ||
    location.pathname === "/groups" ||
    location.pathname === "/switch-user" ||
    location.pathname.startsWith("/clients") ||
    location.pathname === "/policy" ||
    location.pathname === "/google-workspace" ||
    location.pathname === "/branding";

  if (collapsed) {
    return (
      <div className="shell">
        <button
          type="button"
          className="shell__reopen"
          onClick={() => setCollapsed(false)}
          aria-label="Show sidebar"
          title="Show sidebar"
        >
          »
        </button>
        <div className="shell__body shell__body--full">
          {backBar}
          {children}
        </div>
      </div>
    );
  }

  return (
    <div className="shell">
      <aside className="shell__sidebar">
        <div className="shell__sidebar-top">
          <div className="shell__brand">
            {branding?.logoUrl ? (
              <img src={branding.logoUrl} alt={session?.tenantName ?? "Logo"} className="shell__brand-logo" />
            ) : (
              <>
                <span className="shell__brand-mark">{session?.tenantName ? session.tenantName.charAt(0).toUpperCase() : "IAM"}</span>
                <span className="shell__brand-name">{session?.tenantName ?? "Platform"}</span>
              </>
            )}
          </div>
          <button
            type="button"
            className="shell__collapse"
            onClick={() => setCollapsed(true)}
            aria-label="Hide sidebar"
            title="Hide sidebar"
          >
            «
          </button>
        </div>

        <nav className="shell__nav">
          <NavSection>
            <NavLink to="/" icon="dashboard" label="Dashboard" active={location.pathname === "/"} />
            <NavLink to="/apps" icon="apps" label="My Apps" active={location.pathname === "/apps"} />
            <NavLink to="/my-security" icon="shield" label="My Security" active={location.pathname === "/my-security"} />
          </NavSection>

          {admin && (
            <div className="shell__nav-section">
              <button
                type="button"
                className="shell__nav-collapsible"
                onClick={() => setAdminOpen((v) => !v)}
                aria-expanded={adminOpen}
              >
                <span>Administration</span>
                <span className={adminOpen ? "shell__chevron shell__chevron--open" : "shell__chevron"}>›</span>
              </button>
              {(adminOpen || adminIsCurrentSection) && (
                <div className="shell__nav-collapsible-body">
                  <NavLink to="/users" icon="users" label="Users" active={location.pathname === "/users"} />
                  <NavLink to="/groups" icon="groups" label="Groups" active={location.pathname === "/groups"} />
                  <NavLink to="/switch-user" icon="switch" label="Switch to user" active={location.pathname === "/switch-user"} />
                  <NavLink to="/clients" icon="plug" label="Applications" active={location.pathname.startsWith("/clients") || location.pathname === "/google-workspace"} />
                  <NavLink to="/policy" icon="lock" label="Access policy" active={location.pathname === "/policy"} />
                  <NavLink to="/branding" icon="palette" label="Branding" active={location.pathname === "/branding"} />
                </div>
              )}
            </div>
          )}
        </nav>

        <div className="shell__footer">
          <ThemeToggle className="shell__theme-toggle" />
          <div className="shell__identity">
            <span className="shell__avatar">{identityLabel.charAt(0).toUpperCase()}</span>
            <span className="shell__identity-text">
              <span className="shell__identity-name">{identityLabel}</span>
              <span className="shell__identity-meta">
                {admin ? "Admin" : "User"}
                {session?.tenantName ? ` · ${session.tenantName}` : ""}
              </span>
            </span>
          </div>
          <button type="button" className="shell__signout" onClick={() => void handleSignOut()}>
            Sign out
          </button>
        </div>
      </aside>

      <div className="shell__body">
        {backBar}
        {children}
      </div>
    </div>
  );
}

function NavSection({ children }: { children: ReactNode }) {
  return <div className="shell__nav-section">{children}</div>;
}

function NavLink({ to, label, icon, active }: { to: string; label: string; icon: IconName; active: boolean }) {
  return (
    <Link to={to} className={active ? "shell__nav-link shell__nav-link--active" : "shell__nav-link"}>
      <Icon name={icon} />
      <span>{label}</span>
    </Link>
  );
}
