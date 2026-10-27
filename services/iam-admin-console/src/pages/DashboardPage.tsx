import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { isAdmin, loadSession } from "@/lib/session";
import { listTenantUsers } from "@/lib/impersonate";
import { listGroups } from "@/lib/groups";
import { listClients } from "@/lib/oidcClients";
import { listSamlSps } from "@/lib/samlSps";
import { listMyApps } from "@/lib/myApps";
import { getGoogleWorkspaceConfig } from "@/lib/googleWorkspace";
import { PageHeader, StatCard, StatusBadge } from "@/components/ui";

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
  { to: "/groups", title: "Groups", description: "Choose which apps, 2FA and IP rules each group gets.", adminOnly: true },
  { to: "/clients", title: "Applications", description: "Connect a third-party app via OIDC or SAML.", adminOnly: true },
  { to: "/policy", title: "Access policy", description: "Set tenant-wide sign-in and 2FA rules.", adminOnly: true },
];

interface Counts {
  users: number;
  activeUsers: number;
  groups: number;
  apps: number;
  myApps: number;
  googleConfigured: boolean;
}

export function DashboardPage() {
  const session = loadSession()!;
  const admin = isAdmin(session);
  const links = QUICK_LINKS.filter((l) => !l.adminOnly || admin);
  const [counts, setCounts] = useState<Partial<Counts> | null>(null);

  // Each number loads independently: one failing call leaves that card on
  // "—" rather than blanking the whole dashboard.
  useEffect(() => {
    let cancelled = false;
    const t = session.tenantId;
    const tok = session.token;
    const set = (patch: Partial<Counts>) => !cancelled && setCounts((prev) => ({ ...prev, ...patch }));
    setCounts({});

    void listMyApps(t, tok).then((a) => set({ myApps: a.length })).catch(() => undefined);
    if (admin) {
      void listTenantUsers(t, tok)
        .then((u) => set({ users: u.length, activeUsers: u.filter((x) => x.status === "ACTIVE").length }))
        .catch(() => undefined);
      void listGroups(t, tok).then((g) => set({ groups: g.length })).catch(() => undefined);
      void Promise.all([listClients(t, tok), listSamlSps(t, tok)])
        .then(([o, s]) => set({ apps: o.length + s.length }))
        .catch(() => undefined);
      void getGoogleWorkspaceConfig(t, tok)
        .then((c) => set({ googleConfigured: c !== null }))
        .catch(() => undefined);
    }
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const show = (n: number | undefined) => (n === undefined ? "—" : n);

  return (
    <main className="page">
      <PageHeader
        title={`Welcome back${session.tenantName ? `, ${session.tenantName}` : ""}`}
        subtitle={`You're signed in as ${admin ? "an administrator" : "a user"} for this tenant.`}
      />

      <div className="stat-grid">
        {admin ? (
          <>
            <StatCard label="Users" value={show(counts?.users)} hint={counts?.activeUsers === undefined ? undefined : `${counts.activeUsers} active`} to="/users" />
            <StatCard label="Groups" value={show(counts?.groups)} hint="Control app access per group" to="/groups" />
            <StatCard label="Connected apps" value={show(counts?.apps)} hint="OIDC and SAML" to="/clients" />
            <StatCard
              label="Google Workspace"
              value={
                counts?.googleConfigured === undefined ? (
                  "—"
                ) : counts.googleConfigured ? (
                  <StatusBadge tone="success">Connected</StatusBadge>
                ) : (
                  <StatusBadge tone="warning">Not configured</StatusBadge>
                )
              }
              hint="User auto-provisioning"
              to="/google-workspace"
            />
          </>
        ) : (
          <StatCard label="My apps" value={show(counts?.myApps)} hint="Apps you can launch" to="/apps" />
        )}
      </div>

      <div className="section-title">
        <h2>Quick actions</h2>
      </div>
      <div className="quick-links" style={{ marginTop: 0 }}>
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
