import { Link } from "react-router-dom";
import { isAdmin, loadSession } from "@/lib/session";

interface QuickLink {
  to: string;
  title: string;
  description: string;
  adminOnly?: boolean;
}

const QUICK_LINKS: QuickLink[] = [
  { to: "/apps", title: "My Apps", description: "Launch any connected app with the session you already have." },
  { to: "/my-security", title: "My Security", description: "Manage your own two-factor authenticator." },
  { to: "/users", title: "Users", description: "Create and manage accounts for this tenant.", adminOnly: true },
  { to: "/groups", title: "Groups", description: "Control 2FA and IP restrictions per group.", adminOnly: true },
  {
    to: "/clients",
    title: "Applications",
    description: "Connect a third-party app via OIDC single sign-on.",
    adminOnly: true,
  },
  { to: "/policy", title: "Access policy", description: "Set tenant-wide sign-in and 2FA rules.", adminOnly: true },
];

export function DashboardPage() {
  const session = loadSession();
  const admin = isAdmin(session);
  const links = QUICK_LINKS.filter((l) => !l.adminOnly || admin);

  return (
    <main className="page">
      <h1>Welcome back{session?.tenantName ? `, ${session.tenantName}` : ""}</h1>
      <p className="hint">
        You're signed in as {admin ? "an admin" : "a user"} for this tenant.
      </p>

      <div className="quick-links">
        {links.map((link) => (
          <Link key={link.to} to={link.to} className="quick-link-card">
            <span className="quick-link-card__title">{link.title}</span>
            <span className="quick-link-card__desc">{link.description}</span>
          </Link>
        ))}
      </div>
    </main>
  );
}
