import { useEffect, useState } from "react";
import { listGroups, createGroup, assignUserToGroup, type Group } from "@/lib/groups";
import { getPolicy, putPolicy, type Policy } from "@/lib/policy";
import { listTenantUsers, type AdminUserListEntry } from "@/lib/impersonate";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";

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
  const [newGroupName, setNewGroupName] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    setLoading(true);
    setError(null);
    try {
      const [g, u] = await Promise.all([
        listGroups(session.tenantId, session.token),
        listTenantUsers(session.tenantId, session.token),
      ]);
      setGroups(g);
      setUsers(u);
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

  return (
    <main className="page">
      <h1>Groups</h1>
      <p className="hint">
        Each group can require 2FA (or not) and restrict sign-in to specific IP ranges — independently from the
        tenant-wide policy, unless the tenant policy marks a setting as a hard cap.
      </p>

      {error && (
        <p role="alert" className="login-form__error">
          {error}
        </p>
      )}

      <form className="inline-form" onSubmit={(e) => void handleCreateGroup(e)}>
        <input placeholder="New group name (e.g. Finance)" value={newGroupName} onChange={(e) => setNewGroupName(e.target.value)} />
        <button type="submit">Create group</button>
      </form>

      {loading ? (
        <p>Loading…</p>
      ) : groups.length === 0 ? (
        <p>No groups yet.</p>
      ) : (
        groups.map((g) => (
          <GroupCard
            key={g.id}
            group={g}
            users={users}
            tenantId={session.tenantId}
            sessionToken={session.token}
            onAssign={handleAssign}
            onError={setError}
          />
        ))
      )}

      <h2>Users with no group</h2>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Email</th>
            <th>Assign to group</th>
          </tr>
        </thead>
        <tbody>
          {users
            .filter((u) => !u.groupId)
            .map((u) => (
              <tr key={u.id}>
                <td>{u.displayName}</td>
                <td>{u.email}</td>
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
    </main>
  );
}

function GroupCard({
  group,
  users,
  tenantId,
  sessionToken,
  onAssign,
  onError,
}: {
  group: Group;
  users: AdminUserListEntry[];
  tenantId: string;
  sessionToken: string;
  onAssign: (userId: string, groupId: string) => void;
  onError: (msg: string) => void;
}) {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [mfaRequired, setMfaRequired] = useState<"" | "true" | "false">("");
  const [allowedCidrs, setAllowedCidrs] = useState("");
  const [blockedCidrs, setBlockedCidrs] = useState("");
  const [saved, setSaved] = useState(false);

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

  async function savePolicy(e: React.FormEvent) {
    e.preventDefault();
    setSaved(false);
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
    }
  }

  const members = users.filter((u) => u.groupId === group.id);
  const nonMembers = users.filter((u) => u.groupId !== group.id);

  return (
    <div className="callout">
      <h3>{group.name}</h3>
      {saved && <p>Saved.</p>}
      <form onSubmit={(e) => void savePolicy(e)} className="policy-form">
        <label className="login-form__field">
          2FA for this group
          <select value={mfaRequired} onChange={(e) => setMfaRequired(e.target.value as "" | "true" | "false")}>
            <option value="">Inherit from tenant policy</option>
            <option value="true">Required (2FA)</option>
            <option value="false">Not required (password only)</option>
          </select>
        </label>
        <label className="login-form__field">
          Allowed IP ranges (CIDR, comma-separated — leave blank to allow any IP)
          <input value={allowedCidrs} onChange={(e) => setAllowedCidrs(e.target.value)} placeholder="203.0.113.0/24" />
        </label>
        <label className="login-form__field">
          Blocked IP ranges (CIDR, comma-separated)
          <input value={blockedCidrs} onChange={(e) => setBlockedCidrs(e.target.value)} />
        </label>
        <button type="submit">Save group policy</button>
      </form>

      <p className="hint">Members:</p>
      {members.length === 0 ? (
        <p className="hint">No members yet.</p>
      ) : (
        <ul>
          {members.map((u) => (
            <li key={u.id}>
              {u.displayName} ({u.email}){" "}
              <button type="button" onClick={() => onAssign(u.id, "")}>
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}

      <p className="hint">Add a member:</p>
      <select defaultValue="" onChange={(e) => e.target.value && onAssign(e.target.value, group.id)}>
        <option value="" disabled>
          Choose a user…
        </option>
        {nonMembers.map((u) => (
          <option key={u.id} value={u.id}>
            {u.displayName} ({u.email})
          </option>
        ))}
      </select>
      {policy === null && <p className="hint">No policy saved yet for this group — defaults to the tenant-wide policy.</p>}
    </div>
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
