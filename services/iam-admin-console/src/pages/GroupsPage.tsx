import { useEffect, useState } from "react";
import { listGroups, createGroup, assignUserToGroup, deleteGroup, deleteGroupOrgUnit, type Group } from "@/lib/groups";
import { getPolicy, putPolicy, type Policy } from "@/lib/policy";
import { listTenantUsers, type AdminUserListEntry } from "@/lib/impersonate";
import { getAppGroups, setAppGroups, type AppKind } from "@/lib/appGroups";
import { pushGroupToOrgUnit } from "@/lib/googleWorkspace";
import { listClients } from "@/lib/oidcClients";
import { listSamlSps } from "@/lib/samlSps";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import {
  Alert,
  AppIcon,
  Avatar,
  EmptyState,
  PageHeader,
  Pagination,
  PendingLabel,
  SkeletonRows,
  StatusBadge,
  TableToolbar,
} from "@/components/ui";
import { useConfirm, useToast } from "@/components/feedback";
import { useTable } from "@/lib/useTable";

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
  const toast = useToast();
  const confirm = useConfirm();
  const [groups, setGroups] = useState<Group[]>([]);
  const [users, setUsers] = useState<AdminUserListEntry[]>([]);
  const [apps, setApps] = useState<GroupApp[]>([]);
  const [newGroupName, setNewGroupName] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function refresh(showSkeleton = true) {
    if (showSkeleton) setLoading(true);
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
      setError("Enter an OU name.");
      return;
    }
    try {
      await createGroup(session.tenantId, newGroupName.trim(), session.token);
      setNewGroupName("");
      toast.success("OU created.");
      await refresh(false);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  async function handleAssign(userId: string, groupId: string) {
    try {
      await assignUserToGroup(session.tenantId, userId, groupId || null, session.token);
      toast.success(groupId ? "Member added." : "Member removed.");
      await refresh(false);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  async function handleDeleteGroup(group: Group) {
    const ok = await confirm({
      title: `Delete "${group.name}"?`,
      message: "Its members will be unassigned and its app access removed. The users and apps themselves are not deleted.",
      confirmLabel: "Delete OU",
      danger: true,
    });
    if (!ok) return;
    try {
      await deleteGroup(session.tenantId, group.id, session.token);
      toast.success("OU deleted.");
      await refresh(false);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  const unassigned = users.filter((u) => !u.groupId);
  const unassignedTable = useTable(unassigned, {
    searchText: (u) => `${u.displayName} ${u.email}`,
    sorters: { name: (a, b) => a.displayName.localeCompare(b.displayName) },
    initialSort: { key: "name", dir: "asc" },
    pageSize: 10,
  });

  return (
    <main className="page">
      <PageHeader
        title="OUs"
        subtitle="An OU decides which apps its members can open, whether they need 2FA, and which IP ranges they can sign in from. These apply on top of the tenant-wide policy unless it marks a setting as a hard cap."
      />

      {error && <Alert kind="error">{error}</Alert>}

      <form className="inline-form" style={{ marginTop: 0 }} onSubmit={(e) => void handleCreateGroup(e)}>
        <input placeholder="New OU name (e.g. Finance)" value={newGroupName} onChange={(e) => setNewGroupName(e.target.value)} />
        <button type="submit">+ Create OU</button>
      </form>

      {loading ? (
        <SkeletonRows rows={3} />
      ) : groups.length === 0 ? (
        <EmptyState
          title="No OUs yet"
          description="Create an OU above, then tick the apps its members should be able to open."
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
        <h2>Users with no OU</h2>
      </div>
      {loading ? null : unassigned.length === 0 ? (
        <EmptyState title="Everyone is in an OU" description="Users without an OU can't open any apps." />
      ) : (
        <>
        <TableToolbar
          query={unassignedTable.query}
          onQuery={unassignedTable.setQuery}
          placeholder="Search users without an OU"
          summary={`${unassignedTable.filteredCount} of ${unassignedTable.total}`}
        />
        <div className="card table-card">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Assign to OU</th>
              </tr>
            </thead>
            <tbody>
              {unassignedTable.filteredCount === 0 && (
                <tr className="table-empty-row">
                  <td colSpan={2}>No users match "{unassignedTable.query}".</td>
                </tr>
              )}
              {unassignedTable.pageRows.map((u) => (
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
                          Choose an OU…
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
          <Pagination
            page={unassignedTable.page}
            pageCount={unassignedTable.pageCount}
            pageSize={unassignedTable.pageSize}
            filteredCount={unassignedTable.filteredCount}
            onPage={unassignedTable.setPage}
            onPageSize={unassignedTable.setPageSize}
          />
        </div>
        </>
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
  const [allowedCidrs, setAllowedCidrs] = useState<string[]>([""]);
  const [blockedCidrs, setBlockedCidrs] = useState<string[]>([""]);
  const toast = useToast();
  const confirm = useConfirm();
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [pushingToGoogle, setPushingToGoogle] = useState(false);
  const [deletingOu, setDeletingOu] = useState(false);

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
        setAllowedCidrs(p.allowedCidrs && p.allowedCidrs.length > 0 ? p.allowedCidrs : [""]);
        setBlockedCidrs(p.blockedCidrs && p.blockedCidrs.length > 0 ? p.blockedCidrs : [""]);
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
      toast.success(checked ? `${app.name} added to ${group.name}.` : `${app.name} removed from ${group.name}.`);
    } catch (err) {
      setAppError(errorMessage(err));
    } finally {
      setSavingApp(null);
    }
  }

  async function savePolicy(e: React.FormEvent) {
    e.preventDefault();
    setSavingPolicy(true);
    try {
      await putPolicy(
        {
          tenantId,
          scope: "OU",
          scopeId: group.id,
          mfaRequired: mfaRequired === "" ? null : mfaRequired === "true",
          allowedCidrs: toList(allowedCidrs.join(", ")),
          blockedCidrs: toList(blockedCidrs.join(", ")),
        },
        sessionToken,
      );
      toast.success("OU policy saved.");
    } catch (err) {
      onError(errorMessage(err));
    } finally {
      setSavingPolicy(false);
    }
  }

  // Pushes this group INTO Google as an OU -- the reverse of the Organizational units page's sync
  // button. See GoogleWorkspaceGroupPushService's doc comment (iam-tenant-svc): moves current members
  // into the OU (creating it first if needed), never creates a Google account, never removes anyone
  // from the OU later just because they left the group. A real structural move on Google's side --
  // OU-scoped Google policies (2-Step Verification, SSO profiles) can apply differently afterward.
  async function pushToGoogle() {
    const ok = await confirm({
      title: "Push this OU to Google Workspace?",
      message: (
        <>
          Every current member of <strong>{group.name}</strong> who has a Google account on your configured
          domain will be moved into a Google org unit named <strong>{group.name}</strong> (created if it
          doesn't exist yet). This changes their real organizational unit in Google, which can change which
          Google-side policies apply to them (2-Step Verification, SSO). Members without a matching Google
          account are skipped, not created.
        </>
      ),
      confirmLabel: "Push to Google",
      danger: true,
    });
    if (!ok) return;

    setPushingToGoogle(true);
    try {
      const result = await pushGroupToOrgUnit(tenantId, group.id, sessionToken);
      const lead = `${result.created ? "Created" : "Reused"} ${result.orgUnitPath} in Google; moved ${result.moved.length} member${result.moved.length === 1 ? "" : "s"}.`;
      if (result.skipped.length > 0) {
        toast.error(`${lead} ${result.skipped.length} member${result.skipped.length === 1 ? "" : "s"} skipped (no matching Google account): ${result.skipped.join(", ")}.`);
      } else {
        toast.success(lead);
      }
    } catch (err) {
      onError(errorMessage(err));
    } finally {
      setPushingToGoogle(false);
    }
  }

  // Separate from deleting the IAM group -- deleting the group never touches Google on its own (see
  // GroupController.deleteGroup / GoogleWorkspaceGroupPushService). Google refuses to delete a
  // non-empty OU, so this will fail with a clear message unless everyone's already been moved out.
  async function deleteOu() {
    const ok = await confirm({
      title: "Delete this OU's Google org unit?",
      message: (
        <>
          Deletes the Google org unit named <strong>{group.name}</strong>, if one exists. This does not delete
          or suspend anyone's Google account, and does not delete this OU in IAM. Google will refuse this if the
          org unit still has anyone in it -- move everyone out first (push them to a different OU's Google org
          unit, or move them in Google directly).
        </>
      ),
      confirmLabel: "Delete org unit",
      danger: true,
    });
    if (!ok) return;

    setDeletingOu(true);
    try {
      await deleteGroupOrgUnit(tenantId, group.id, sessionToken);
      toast.success(`Deleted (or confirmed absent) the Google org unit for ${group.name}.`);
    } catch (err) {
      onError(errorMessage(err));
    } finally {
      setDeletingOu(false);
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
        <div className="row-actions">
          <button type="button" className="btn-secondary btn-sm" disabled={pushingToGoogle} onClick={() => void pushToGoogle()}>
            <PendingLabel pending={pushingToGoogle} idle="Push to Google as OU" busy="Pushing…" />
          </button>
          <button type="button" className="btn-danger btn-sm" disabled={deletingOu} onClick={() => void deleteOu()}>
            <PendingLabel pending={deletingOu} idle="Delete Google OU" busy="Deleting…" />
          </button>
          <button type="button" className="btn-danger btn-sm" onClick={() => onDelete(group)}>
            Delete OU
          </button>
        </div>
      </div>

      <div className="group-card__section" style={{ marginTop: 0, paddingTop: 0, borderTop: "none" }}>
        <h4 className="group-card__section-title">Apps this OU can open</h4>
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
        <form onSubmit={(e) => void savePolicy(e)} className="policy-form" style={{ maxWidth: "none" }}>
          <div className="form-grid">
            <label className="login-form__field">
              2FA for this OU
              <select value={mfaRequired} onChange={(e) => setMfaRequired(e.target.value as "" | "true" | "false")}>
                <option value="">Inherit from tenant policy</option>
                <option value="true">Required (2FA)</option>
                <option value="false">Not required (password only)</option>
              </select>
            </label>
            <span />
            <div className="login-form__field form-grid__full">
              Allowed IP ranges (blank allows any IP)
              <CidrRangeRows values={allowedCidrs} onChange={setAllowedCidrs} placeholder="203.0.113.0/24" />
            </div>
            <div className="login-form__field form-grid__full">
              Blocked IP ranges
              <CidrRangeRows values={blockedCidrs} onChange={setBlockedCidrs} placeholder="198.51.100.0/24" />
            </div>
          </div>
          {policy === null && (
            <p className="hint" style={{ margin: 0 }}>
              No policy saved yet for this OU, so it follows the tenant-wide policy.
            </p>
          )}
          <div className="form-actions" style={{ marginTop: 4 }}>
            <button type="submit" disabled={savingPolicy}>
              <PendingLabel pending={savingPolicy} idle="Save OU policy" busy="Saving…" />
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

/**
 * One row per IP range instead of a single comma-separated box -- makes it practical to build up a
 * list of office/location ranges (Delhi, Mumbai, a VPN exit, ...) one at a time without having to
 * punctuate a long string by hand. Still saved as the same plain comma-separated list the policy
 * engine has always taken; this only changes how it's edited, not how it's stored.
 */
function CidrRangeRows({
  values,
  onChange,
  placeholder,
}: {
  values: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
}) {
  return (
    <>
      {values.map((v, i) => (
        <div className="setup-form__repeat-row" key={i}>
          <input
            value={v}
            onChange={(e) => onChange(values.map((old, idx) => (idx === i ? e.target.value : old)))}
            placeholder={placeholder}
          />
          <button
            type="button"
            className="btn-secondary"
            onClick={() => onChange(values.filter((_, idx) => idx !== i))}
            disabled={values.length === 1}
          >
            &minus;
          </button>
        </div>
      ))}
      <button type="button" className="btn-secondary" onClick={() => onChange([...values, ""])}>
        + Add another range
      </button>
    </>
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
