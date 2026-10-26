import { useEffect, useState, type ReactNode } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { clearSession, isAdmin, loadSession } from "@/lib/session";
import { ThemeToggle } from "@/components/ThemeToggle";

const SIDEBAR_COLLAPSED_KEY = "iam-admin-console:sidebar-collapsed";
const ADMIN_SECTION_OPEN_KEY = "iam-admin-console:admin-nav-open";

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

  function handleSignOut() {
    clearSession();
    navigate("/login");
  }

  const identityLabel = session?.email ?? session?.tenantName ?? "Signed in";
  const adminIsCurrentSection =
    location.pathname === "/users" ||
    location.pathname === "/groups" ||
    location.pathname === "/switch-user" ||
    location.pathname.startsWith("/clients") ||
    location.pathname === "/policy";

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
        <div className="shell__body shell__body--full">{children}</div>
      </div>
    );
  }

  return (
    <div className="shell">
      <aside className="shell__sidebar">
        <div className="shell__sidebar-top">
          <div className="shell__brand">
            <span className="shell__brand-mark">IAM</span>
            <span className="shell__brand-name">Platform</span>
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
            <NavLink to="/" label="Dashboard" active={location.pathname === "/"} />
            <NavLink to="/apps" label="My Apps" active={location.pathname === "/apps"} />
            <NavLink to="/my-security" label="My Security" active={location.pathname === "/my-security"} />
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
                  <NavLink to="/users" label="Users" active={location.pathname === "/users"} />
                  <NavLink to="/groups" label="Groups" active={location.pathname === "/groups"} />
                  <NavLink to="/switch-user" label="Switch to user" active={location.pathname === "/switch-user"} />
                  <NavLink to="/clients" label="Applications" active={location.pathname.startsWith("/clients")} />
                  <NavLink to="/policy" label="Access policy" active={location.pathname === "/policy"} />
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
          <button type="button" className="shell__signout" onClick={handleSignOut}>
            Sign out
          </button>
        </div>
      </aside>

      <div className="shell__body">{children}</div>
    </div>
  );
}

function NavSection({ children }: { children: ReactNode }) {
  return <div className="shell__nav-section">{children}</div>;
}

function NavLink({ to, label, active }: { to: string; label: string; active: boolean }) {
  return (
    <Link to={to} className={active ? "shell__nav-link shell__nav-link--active" : "shell__nav-link"}>
      {label}
    </Link>
  );
}
