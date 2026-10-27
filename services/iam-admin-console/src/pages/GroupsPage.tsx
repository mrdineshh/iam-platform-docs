import { useEffect, useState } from "react";
import { listGroups, createGroup, assignUserToGroup, deleteGroup, type Group } from "@/lib/groups";
import { getPolicy, putPolicy, type Policy } from "@/lib/policy";
import { listTenantUsers, type AdminUserListEntry } from "@/lib/impersonate";
import { getAppGroups, setAppGroups, type AppKind } from "@/lib/appGroups";
import { listClients } from "@/lib/oidcClients";
import { listSamlSps } from "@/lib/samlSps";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import { Alert, AppIcon, Avatar, EmptyState, PageHeader, PendingLabel, SkeletonRows, StatusBadge } from "@/components/ui";

// Same "connected app" shape ClientsPage builds, just the minimum this page
// needs: id/name/kind to drive the per-group app checkboxes below.
interface GroupApp {
  id: string;
  name: string;
  kind: AppKind;
}

/**
 * Admin-only. A group IS an OU for policy purposes (iam-policy-svc's
 * PolicyScope.OU) -- each group's card edits that group's OU-scoped policy
 * directly (2FA requirement, allowed/blocked IP ranges), same engine and
 * merge rules as the tenant-wide policy page, just scoped to this group's
 * members instead of everyone.
 */
export function GroupsPage() {
  const session = loadSession()!;
  const [groups, setGroups] = useState<Group[]>([]);
  const [users, setUsers] = useState<AdminUserListEntry[]>([]);
  const [apps, setApps] = useState<GroupApp[]>([]);
  const [newGroupName, setNewGroupName] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    setLoading(true);
    setError(null);
    try {
      const [g, u, oidcClients, samlSps] = await Promise.all([
        listGroups(session.tenantId, session.token),
        listTenantUsers(session.tenantId, session.token),
        listClients(session.tenantId, session.token),
        listSamlSps(session.tenantId, session.token),
      ]);
      setGroups(g);
      setUsers(u);
      setApps([
        ...oidcClients.map((c) => ({ id: c.clientId, name: c.name, kind: "oidc-clients" as const })),
        ...samlSps.map((s) => ({ id: s.id, name: s.name, kind: "saml-sps" as const })),
      ]);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleCreateGroup(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!newGroupName.trim()) {
      setError("Enter a group name.");
      return;
    }
    try {
      await createGroup(session.tenantId, newGroupName.trim(), session.token);
      setNewGroupName("");
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function handleAssign(userId: string, groupId: string) {
    setError(null);
    try {
      await assignUserToGroup(session.tenantId, userId, groupId || null, session.token);
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function handleDeleteGroup(group: Group) {
    if (!window.confirm(`Delete "${group.name}"? Its members will be unassigned and its app access removed.`)) return;
    setError(null);
    try {
      await deleteGroup(session.tenantId, group.id, session.token);
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <main className="page">
      <PageHeader
        title="Groups"
        subtitle="A group decides which apps its members can open, whether they need 2FA, and which IP ranges they can sign in from. These apply on top of the tenant-wide policy unless it marks a setting as a hard cap."
      />

      {error && <Alert kind="error">{error}</Alert>}

      <form className="inline-form" style={{ marginTop: 0 }} onSubmit={(e) => void handleCreateGroup(e)}>
        <input placeholder="New group name (e.g. Finance)" value={newGroupName} onChange={(e) => setNewGroupName(e.target.value)} />
        <button type="submit">+ Create group</button>
      </form>

      {loading ? (
        <SkeletonRows rows={3} />
      ) : groups.length === 0 ? (
        <EmptyState
          title="No groups yet"
          description="Create a group above, then tick the apps its members should be able to open."
        />
      ) : (
        groups.map((g) => (
          <GroupCard
            key={g.id}
            group={g}
            users={users}
            apps={apps}
            tenantId={session.tenantId}
            sessionToken={session.token}
            onAssign={handleAssign}
            onDelete={handleDeleteGroup}
            onError={setError}
          />
        ))
      )}

      <div className="section-title">
        <h2>Users with no group</h2>
      </div>
      {loading ? null : users.filter((u) => !u.groupId).length === 0 ? (
        <EmptyState title="Everyone is in a group" description="Users without a group can't open any apps." />
      ) : (
        <div className="card table-card">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Assign to group</th>
              </tr>
            </thead>
            <tbody>
              {users
                .filter((u) => !u.groupId)
                .map((u) => (
                  <tr key={u.id}>
                    <td>
                      <div className="cell-user">
                        <Avatar name={u.displayName} />
                        <div>
                          <div className="cell-user__name">{u.displayName}</div>
                          <div className="cell-user__sub">{u.email}</div>
                        </div>
                      </div>
                    </td>
                    <td>
                      <select defaultValue="" onChange={(e) => void handleAssign(u.id, e.target.value)}>
                        <option value="" disabled>
                          Choose a group…
                        </option>
                        {groups.map((g) => (
                          <option key={g.id} value={g.id}>
                            {g.name}
                          </option>
                        ))}
                      </select>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}

function GroupCard({
  group,
  users,
  apps,
  tenantId,
  sessionToken,
  onAssign,
  onDelete,
  onError,
}: {
  group: Group;
  users: AdminUserListEntry[];
  apps: GroupApp[];
  tenantId: string;
  sessionToken: string;
  onAssign: (userId: string, groupId: string) => void;
  onDelete: (group: Group) => void;
  onError: (msg: string) => void;
}) {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [mfaRequired, setMfaRequired] = useState<"" | "true" | "false">("");
  const [allowedCidrs, setAllowedCidrs] = useState("");
  const [blockedCidrs, setBlockedCidrs] = useState("");
  const [saved, setSaved] = useState(false);
  const [savingPolicy, setSavingPolicy] = useState(false);

  // Per-app "is this app assigned to this group" state, keyed by app id.
  // Loaded from the same getAppGroups/setAppGroups endpoints ClientsPage
  // uses -- this is just the inverse view (pick apps for a group, instead
  // of picking groups for an app), same underlying many-to-many data.
  const [appAssigned, setAppAssigned] = useState<Map<string, boolean> | null>(null);
  const [appError, setAppError] = useState<string | null>(null);
  const [savingApp, setSavingApp] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const p = await getPolicy(tenantId, "OU", group.id, sessionToken);
      setPolicy(p);
      if (p) {
        setMfaRequired(p.mfaRequired === null ? "" : p.mfaRequired ? "true" : "false");
        setAllowedCidrs((p.allowedCidrs ?? []).join(", "));
        setBlockedCidrs((p.blockedCidrs ?? []).join(", "));
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [group.id]);

  useEffect(() => {
    (async () => {
      setAppError(null);
      try {
        const entries = await Promise.all(
          apps.map(async (app) => {
            const groupIds = await getAppGroups(app.kind, app.id, tenantId, sessionToken);
            return [app.id, groupIds.includes(group.id)] as const;
          }),
        );
        setAppAssigned(new Map(entries));
      } catch (err) {
        setAppError(errorMessage(err));
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [group.id, apps]);

  async function toggleApp(app: GroupApp, checked: boolean) {
    setAppError(null);
    setSavingApp(app.id);
    try {
      const currentGroupIds = await getAppGroups(app.kind, app.id, tenantId, sessionToken);
      const nextGroupIds = checked
        ? Array.from(new Set([...currentGroupIds, group.id]))
        : currentGroupIds.filter((id) => id !== group.id);
      await setAppGroups(app.kind, app.id, tenantId, nextGroupIds, sessionToken);
      setAppAssigned((prev) => {
        const next = new Map(prev ?? []);
        next.set(app.id, checked);
        return next;
      });
    } catch (err) {
      setAppError(errorMessage(err));
    } finally {
      setSavingApp(null);
    }
  }

  async function savePolicy(e: React.FormEvent) {
    e.preventDefault();
    setSaved(false);
    setSavingPolicy(true);
    try {
      await putPolicy(
        {
          tenantId,
          scope: "OU",
          scopeId: group.id,
          mfaRequired: mfaRequired === "" ? null : mfaRequired === "true",
          allowedCidrs: toList(allowedCidrs),
          blockedCidrs: toList(blockedCidrs),
        },
        sessionToken,
      );
      setSaved(true);
    } catch (err) {
      onError(errorMessage(err));
    } finally {
      setSavingPolicy(false);
    }
  }

  const members = users.filter((u) => u.groupId === group.id);
  const nonMembers = users.filter((u) => u.groupId !== group.id);

  return (
    <section className="card card--padded group-card">
      <div className="group-card__header">
        <h3>
          {group.name} <StatusBadge tone="neutral">{members.length} member{members.length === 1 ? "" : "s"}</StatusBadge>
        </h3>
        <button type="button" className="btn-danger btn-sm" onClick={() => onDelete(group)}>
          Delete group
        </button>
      </div>

      <div className="group-card__section" style={{ marginTop: 0, paddingTop: 0, borderTop: "none" }}>
        <h4 className="group-card__section-title">Apps this group can open</h4>
        {appError && <Alert kind="error">{appError}</Alert>}
        {appAssigned === null ? (
          <div className="skeleton skeleton--row" />
        ) : apps.length === 0 ? (
          <p className="hint">No apps connected yet. Add one on the Applications page and it will appear here.</p>
        ) : (
          <div className="checkbox-list">
            {apps.map((app) => (
              <label key={app.id} className="checkbox-list__item">
                <input
                  type="checkbox"
                  checked={appAssigned.get(app.id) ?? false}
                  disabled={savingApp === app.id}
                  onChange={(e) => void toggleApp(app, e.target.checked)}
                />
                <AppIcon name={app.name} size={22} />
                {app.name}
              </label>
            ))}
          </div>
        )}
      </div>

      <div className="group-card__section">
        <h4 className="group-card__section-title">Sign-in policy</h4>
        {saved && <Alert kind="success">Group policy saved.</Alert>}
        <form onSubmit={(e) => void savePolicy(e)} className="policy-form" style={{ maxWidth: "none" }}>
          <div className="form-grid">
            <label className="login-form__field">
              2FA for this group
              <select value={mfaRequired} onChange={(e) => setMfaRequired(e.target.value as "" | "true" | "false")}>
                <option value="">Inherit from tenant policy</option>
                <option value="true">Required (2FA)</option>
                <option value="false">Not required (password only)</option>
              </select>
            </label>
            <span />
            <label className="login-form__field">
              Allowed IP ranges (CIDR, comma-separated; blank allows any IP)
              <input value={allowedCidrs} onChange={(e) => setAllowedCidrs(e.target.value)} placeholder="203.0.113.0/24" />
            </label>
            <label className="login-form__field">
              Blocked IP ranges (CIDR, comma-separated)
              <input value={blockedCidrs} onChange={(e) => setBlockedCidrs(e.target.value)} />
            </label>
          </div>
          {policy === null && (
            <p className="hint" style={{ margin: 0 }}>
              No policy saved yet for this group, so it follows the tenant-wide policy.
            </p>
          )}
          <div className="form-actions" style={{ marginTop: 4 }}>
            <button type="submit" disabled={savingPolicy}>
              <PendingLabel pending={savingPolicy} idle="Save group policy" busy="Saving…" />
            </button>
          </div>
        </form>
      </div>

      <div className="group-card__section">
        <h4 className="group-card__section-title">Members</h4>
        {members.length === 0 ? (
          <p className="hint">No members yet.</p>
        ) : (
          <ul className="member-list">
            {members.map((u) => (
              <li key={u.id}>
                <span className="cell-user">
                  <Avatar name={u.displayName} />
                  <span>
                    <span className="cell-user__name">{u.displayName}</span>
                    <br />
                    <span className="cell-user__sub">{u.email}</span>
                  </span>
                </span>
                <button type="button" className="btn-secondary btn-sm" onClick={() => onAssign(u.id, "")}>
                  Remove
                </button>
              </li>
            ))}
          </ul>
        )}
        <select defaultValue="" onChange={(e) => e.target.value && onAssign(e.target.value, group.id)}>
          <option value="" disabled>
            + Add a member…
          </option>
          {nonMembers.map((u) => (
            <option key={u.id} value={u.id}>
              {u.displayName} ({u.email})
            </option>
          ))}
        </select>
      </div>
    </section>
  );
}

function toList(value: string): string[] | null {
  const items = value
    .split(",")
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
  return items.length > 0 ? items : null;
}

function errorMessage(err: unknown): string {
  if (err instanceof UpstreamError) {
    if (err.status === 401) return "Your session expired. Please sign in again.";
    if (err.status === 403) return "You don't have permission to do this.";
    return "This is temporarily unavailable. Please try again.";
  }
  return "This is temporarily unavailable. Please try again.";
}
