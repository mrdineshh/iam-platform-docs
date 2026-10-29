import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { isAdmin, loadSession } from "@/lib/session";
import { listTenantUsers } from "@/lib/impersonate";
import { listGroups } from "@/lib/groups";
import { listClients } from "@/lib/oidcClients";
import { listSamlSps } from "@/lib/samlSps";
import { listMyApps } from "@/lib/myApps";
import { getGoogleWorkspaceConfig } from "@/lib/googleWorkspace";
import { StatCard, StatusBadge } from "@/components/ui";
import { Icon, type IconName } from "@/components/icons";

interface Counts {
  users: number;
  activeUsers: number;
  groups: number;
  apps: number;
  myApps: number;
  googleConfigured: boolean;
}

const ADMIN_ACTIONS: Array<{ to: string; icon: IconName; title: string; desc: string }> = [
  { to: "/users", icon: "users", title: "Add or manage users", desc: "Create accounts, suspend or reactivate access." },
  { to: "/clients", icon: "plug", title: "Connect an application", desc: "OIDC, SAML and SCIM provisioning for your apps." },
  { to: "/groups", icon: "groups", title: "Set group access", desc: "Choose which groups can open which apps." },
  { to: "/policy", icon: "lock", title: "Review access policy", desc: "Sign-in rules, MFA and network controls." },
];

export function DashboardPage() {
  const session = loadSession()!;
  const admin = isAdmin(session);
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
      <section className="hero">
        <div className="hero__text">
          <span className="hero__eyebrow">{admin ? "Administrator console" : "Your workspace"}</span>
          <h1>Welcome back{session.tenantName ? `, ${session.tenantName}` : ""}</h1>
          <p>
            {admin
              ? "Manage who can sign in, which apps they can open, and how access is provisioned — all in one place."
              : "Open your apps and keep your account secure from here."}
          </p>
          <div className="hero__actions">
            <Link to="/apps" className="hero__btn hero__btn--primary">
              Open my apps <Icon name="arrow" size={16} />
            </Link>
            {admin && (
              <Link to="/users" className="hero__btn">
                Manage users
              </Link>
            )}
          </div>
        </div>
        <div className="hero__orb" aria-hidden="true">
          <Icon name="shield" size={64} />
        </div>
      </section>

      <div className="stat-grid">
        {admin ? (
          <>
            <StatCard icon="users" label="Users" value={show(counts?.users)} hint={counts?.activeUsers === undefined ? undefined : `${counts.activeUsers} active`} to="/users" />
            <StatCard icon="groups" label="Groups" value={show(counts?.groups)} hint="Control app access per group" to="/groups" />
            <StatCard icon="plug" label="Connected apps" value={show(counts?.apps)} hint="OIDC and SAML" to="/clients" />
            <StatCard
              icon="cloud"
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
          <StatCard icon="apps" label="My apps" value={show(counts?.myApps)} hint="Apps you can launch" to="/apps" />
        )}
      </div>

      {admin && (
        <>
          <div className="section-title">
            <h2>Quick actions</h2>
          </div>
          <div className="action-grid">
            {ADMIN_ACTIONS.map((a) => (
              <Link key={a.to} to={a.to} className="action-card">
                <span className="action-card__icon">
                  <Icon name={a.icon} size={20} />
                </span>
                <span className="action-card__title">{a.title}</span>
                <span className="action-card__desc">{a.desc}</span>
              </Link>
            ))}
          </div>
        </>
      )}
    </main>
  );
}
