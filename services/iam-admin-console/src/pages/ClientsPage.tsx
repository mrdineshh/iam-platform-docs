import { Fragment, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listClients, type OidcClient } from "@/lib/oidcClients";
import { listSamlSps, type SamlSp } from "@/lib/samlSps";
import { getAppGroups, setAppGroups, type AppKind } from "@/lib/appGroups";
import { listGroups, type Group } from "@/lib/groups";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import {
  Alert,
  AppIcon,
  EmptyState,
  PageHeader,
  Pagination,
  PendingLabel,
  SkeletonRows,
  SortableTh,
  StatusBadge,
  TableToolbar,
} from "@/components/ui";
import { useToast } from "@/components/feedback";
import { AppProvisioningPanel } from "@/components/AppProvisioningPanel";
import { useTable } from "@/lib/useTable";

// A few enterprise/dev tools that plausibly support a custom OIDC login
// (unlike consumer services like real Gmail, which don't let a third party
// act as their identity provider) -- browsing aid only. Clicking any tile
// still goes through the exact same registration flow as "Add a custom
// app": we generate the Client ID/Secret (AP-3, we're the IdP, never the
// other way around), the admin pastes those into that tool's own SSO
// settings. Nothing here is a real pre-built integration.
//
// `logoSlug` is the brand's slug on Simple Icons (simpleicons.org) -- a
// free, MIT-licensed CDN of brand marks built for exactly this use
// (showing a product's own logo to represent it in a directory/catalog
// UI), same as what every real app-launcher/SSO dashboard does.
//
// Google Workspace is the one entry here that defaults to `type: "saml"`
// -- Google's own third-party SSO profile setting only accepts SAML, not
// OIDC (see AppSetupPage.tsx).
const CATALOG = [
  { name: "GitLab", description: "Git repository hosting and CI/CD.", logoSlug: "gitlab", type: "oidc" },
  { name: "Jira", description: "Issue tracking and project management.", logoSlug: "jira", type: "oidc" },
  { name: "Confluence", description: "Team documentation and wikis.", logoSlug: "confluence", type: "oidc" },
  { name: "Grafana", description: "Metrics dashboards and observability.", logoSlug: "grafana", type: "oidc" },
  { name: "Jenkins", description: "Build and deployment automation.", logoSlug: "jenkins", type: "oidc" },
  { name: "Slack", description: "Team messaging (Enterprise Grid SSO).", logoSlug: "slack", type: "oidc" },
  { name: "Google Workspace", description: "Gmail, Docs, Drive, Calendar (SAML SSO).", logoSlug: "google", type: "saml" },
];

interface ConnectedApp {
  id: string;
  name: string;
  type: "OIDC" | "SAML";
  createdAt: string;
  oidc?: OidcClient;
  saml?: SamlSp;
}

export function ClientsPage() {
  const session = loadSession()!;
  const navigate = useNavigate();
  const [apps, setApps] = useState<ConnectedApp[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const table = useTable(apps, {
    searchText: (a) => `${a.name} ${a.type}`,
    sorters: {
      name: (a, b) => a.name.localeCompare(b.name),
      type: (a, b) => a.type.localeCompare(b.type),
      created: (a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime(),
    },
    initialSort: { key: "created", dir: "desc" },
  });

  function toggleExpanded(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  useEffect(() => {
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const [oidcClients, samlSps, groupList] = await Promise.all([
          listClients(session.tenantId, session.token),
          listSamlSps(session.tenantId, session.token),
          listGroups(session.tenantId, session.token),
        ]);
        const combined: ConnectedApp[] = [
          ...oidcClients.map((c) => ({ id: c.clientId, name: c.name, type: "OIDC" as const, createdAt: c.createdAt, oidc: c })),
          ...samlSps.map((s) => ({ id: s.id, name: s.name, type: "SAML" as const, createdAt: s.createdAt, saml: s })),
        ].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
        setApps(combined);
        setGroups(groupList);
      } catch (err) {
        setError(errorMessage(err));
      } finally {
        setLoading(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <main className="page">
      <PageHeader
        title="Applications"
        subtitle="Connect a third-party app via OIDC or SAML so your users can reach it with the login they already have."
        actions={
          <button type="button" onClick={() => navigate("/clients/setup")}>
            + Add custom app
          </button>
        }
      />

      {error && <Alert kind="error">{error}</Alert>}

      <div className="catalog-grid">
        <div className="catalog-card catalog-card--featured">
          <div className="catalog-card__header">
            <AppIcon name="Google Workspace" size={40} />
            <strong>Google Workspace</strong>
          </div>
          <p className="catalog-card__desc">
            Create, suspend and remove Google accounts automatically when users change here. Connect your domain and service account.
          </p>
          <button type="button" onClick={() => navigate("/google-workspace")}>
            Configure
          </button>
        </div>

        {CATALOG.map((app) => (
          <div key={app.name} className="catalog-card">
            <div className="catalog-card__header">
              <AppLogo name={app.name} slug={app.logoSlug} />
              <strong>{app.name}</strong>
            </div>
            <p className="catalog-card__desc">{app.description}</p>
            <button
              type="button"
              onClick={() => navigate(`/clients/setup?name=${encodeURIComponent(app.name)}&type=${app.type}`)}
            >
              Setup
            </button>
          </div>
        ))}

        <div className="catalog-card catalog-card--add">
          <strong>Add a custom app</strong>
          <p className="catalog-card__desc">Not listed? Connect any app that supports OpenID Connect or SAML.</p>
          <button type="button" onClick={() => navigate("/clients/setup")}>
            Add app
          </button>
        </div>
      </div>

      <div className="section-title">
        <h2>Connected apps {!loading && <span className="hint">({apps.length})</span>}</h2>
      </div>
      {loading ? (
        <SkeletonRows rows={3} />
      ) : apps.length === 0 ? (
        <EmptyState
          title="No apps connected yet"
          description="Pick an app from the catalog above, or add a custom one. Connected apps show up here and in every group's app list automatically."
        />
      ) : (
        <>
        <TableToolbar
          query={table.query}
          onQuery={table.setQuery}
          placeholder="Search connected apps"
          summary={`${table.filteredCount} of ${table.total} apps`}
        />
        <div className="card table-card">
        <table>
          <thead>
            <tr>
              <SortableTh label="Name" sortKey="name" sort={table.sort} onSort={table.toggleSort} />
              <SortableTh label="Type" sortKey="type" sort={table.sort} onSort={table.toggleSort} />
              <SortableTh label="Created" sortKey="created" sort={table.sort} onSort={table.toggleSort} />
              <th></th>
            </tr>
          </thead>
          <tbody>
            {table.filteredCount === 0 && (
              <tr className="table-empty-row">
                <td colSpan={4}>No apps match "{table.query}".</td>
              </tr>
            )}
            {table.pageRows.map((app) => {
              const isOpen = expanded.has(app.id);
              return (
                <Fragment key={app.id}>
                  <tr>
                    <td>
                      <div className="cell-app">
                        <AppIcon name={app.name} size={30} />
                        {app.name}
                      </div>
                    </td>
                    <td>
                      <StatusBadge tone={app.type === "SAML" ? "info" : "neutral"}>{app.type}</StatusBadge>
                    </td>
                    <td>{new Date(app.createdAt).toLocaleString()}</td>
                    <td>
                      <button type="button" className="table-toggle" onClick={() => toggleExpanded(app.id)}>
                        {isOpen ? "Hide details" : "Show details"}
                      </button>
                    </td>
                  </tr>
                  {isOpen && app.oidc && (
                    <tr className="table-details-row">
                      <td colSpan={4}>
                        <div className="table-details">
                          <div>
                            <strong>Client ID</strong>
                            <p>{app.oidc.clientId}</p>
                          </div>
                          <div>
                            <strong>Redirect URIs</strong>
                            <p>{app.oidc.redirectUris.join(", ")}</p>
                          </div>
                          <div>
                            <strong>Launch URL</strong>
                            <p>{app.oidc.launchUrl ?? <em>none</em>}</p>
                          </div>
                        </div>
                        <AppGroupAssignment kind="oidc-clients" appId={app.id} groups={groups} />
                        <AppProvisioningPanel kind="OIDC" appId={app.id} />
                      </td>
                    </tr>
                  )}
                  {isOpen && app.saml && (
                    <tr className="table-details-row">
                      <td colSpan={4}>
                        <div className="table-details">
                          <div>
                            <strong>SP entity ID</strong>
                            <p>{app.saml.spEntityId}</p>
                          </div>
                          <div>
                            <strong>ACS URL</strong>
                            <p>{app.saml.acsUrl}</p>
                          </div>
                          <div>
                            <strong>Launch URL</strong>
                            <p>{app.saml.launchUrl ?? <em>none</em>}</p>
                          </div>
                        </div>
                        <AppGroupAssignment kind="saml-sps" appId={app.id} groups={groups} />
                        <AppProvisioningPanel kind="SAML" appId={app.id} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
        <Pagination
          page={table.page}
          pageCount={table.pageCount}
          pageSize={table.pageSize}
          filteredCount={table.filteredCount}
          onPage={table.setPage}
          onPageSize={table.setPageSize}
        />
        </div>
        </>
      )}
    </main>
  );
}

/** Real brand logo on a fixed white chip (so it stays legible in dark mode
 * too, same as every app-directory UI) -- falls back to the old colored
 * letter avatar if the CDN is unreachable or the slug doesn't resolve. */
function AppLogo({ name, slug }: { name: string; slug: string }) {
  const [failed, setFailed] = useState(false);

  if (failed) {
    return (
      <span className="app-tile__icon" style={{ width: 40, height: 40, fontSize: "1.1rem" }}>
        {name.charAt(0)}
      </span>
    );
  }

  return (
    <span className="catalog-card__logo-chip">
      <img
        src={`https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/${slug}.svg`}
        alt={`${name} logo`}
        width={24}
        height={24}
        onError={() => setFailed(true)}
      />
    </span>
  );
}

/**
 * Which groups may see this app on "My Apps" -- an app with no groups
 * checked is visible to nobody but admins (see MyAppsController's doc
 * comment). Lazily loads the current assignment the first time its
 * details row is expanded, since every connected app's groups don't need
 * fetching up front.
 */
function AppGroupAssignment({ kind, appId, groups }: { kind: AppKind; appId: string; groups: Group[] }) {
  const session = loadSession()!;
  const toast = useToast();
  const [selected, setSelected] = useState<Set<string> | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const groupIds = await getAppGroups(kind, appId, session.tenantId, session.token);
        setSelected(new Set(groupIds));
      } catch (err) {
        setLoadError(errorMessage(err));
      }
      // eslint-disable-next-line react-hooks/exhaustive-deps
    })();
  }, []);

  function toggle(groupId: string) {
    setSaved(false);
    setSelected((prev) => {
      const next = new Set(prev ?? []);
      if (next.has(groupId)) next.delete(groupId);
      else next.add(groupId);
      return next;
    });
  }

  async function save() {
    if (!selected) return;
    setSaving(true);
    setLoadError(null);
    try {
      await setAppGroups(kind, appId, session.tenantId, Array.from(selected), session.token);
      setSaved(true);
      toast.success("Group access saved.");
    } catch (err) {
      setLoadError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="table-details__groups">
      <strong>Visible to groups</strong>
      {loadError && (
        <p role="alert" className="login-form__error">
          {loadError}
        </p>
      )}
      {selected === null ? (
        <p className="hint">Loading…</p>
      ) : groups.length === 0 ? (
        <p className="hint">No groups yet — this app is only visible to admins until you create a group on the Groups page.</p>
      ) : (
        <>
          <div className="checkbox-list">
            {groups.map((g) => (
              <label key={g.id} className="checkbox-list__item">
                <input type="checkbox" checked={selected.has(g.id)} onChange={() => toggle(g.id)} />
                {g.name}
              </label>
            ))}
          </div>
          <button type="button" className="btn-sm" onClick={() => void save()} disabled={saving}>
            {saved ? "Saved" : <PendingLabel pending={saving} idle="Save group access" busy="Saving…" />}
          </button>
        </>
      )}
    </div>
  );
}

function errorMessage(err: unknown): string {
  if (err instanceof UpstreamError) {
    if (err.status === 401) return "Your session expired. Please sign in again.";
    if (err.status === 403) return "You don't have permission to do this.";
    return "This is temporarily unavailable. Please try again.";
  }
  return "This is temporarily unavailable. Please try again.";
}
