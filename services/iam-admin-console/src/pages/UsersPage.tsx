import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { createUser, deleteUser, type CreatedUser } from "@/lib/identity";
import { listTenantUsers, type AdminUserListEntry } from "@/lib/impersonate";
import { getPolicy, putPolicy, type Policy } from "@/lib/policy";
import { listGroups, assignUserToGroup, type Group } from "@/lib/groups";
import { getGoogleWorkspaceConfig } from "@/lib/googleWorkspace";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import { Alert, Avatar, EmptyState, PageHeader, PendingLabel, SkeletonRows, StatusBadge } from "@/components/ui";

// "" / "true" / "false" rather than boolean | null directly -- an HTML
// <select> only ever carries a string value, and this third state
// ("" = inherit from group/tenant policy, AP-4's merge) is a real,
// meaningfully different choice from an explicit true or false, not an
// unset default to collapse away.
type TriState = "" | "true" | "false";

// A real CIDR that matches every IPv4 address -- not "no opinion" (which
// a null/absent value already means and would just inherit the tenant's
// restriction), but an explicit, resolvable override: USER scope beats
// TENANT scope in the merge (AP-4) unless the tenant marks the attribute
// as a hard cap, in which case nothing, not even this, can unblock them --
// see docs/DECISIONS.md: that's intentional, a hard cap is meant to be
// absolute.
const ALLOW_ANY_IP = "0.0.0.0/0";

export function UsersPage() {
  const session = loadSession()!;
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<"ADMIN" | "USER">("USER");
  const [createInGoogleWorkspace, setCreateInGoogleWorkspace] = useState(true);
  const [googleWorkspaceConfigured, setGoogleWorkspaceConfigured] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [justCreated, setJustCreated] = useState<CreatedUser | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);

  const [users, setUsers] = useState<AdminUserListEntry[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  // The full policy per user, not just derived flags -- putPolicy fully
  // overwrites a policy row rather than merging (confirmed in
  // iam-policy-svc's PolicyService.putPolicy: every field is assigned
  // unconditionally from the request). Two independent controls on this
  // page (2FA, "allow any IP") both write to the same USER-scope row, so
  // each write has to carry the other's current value forward or it
  // silently wipes it -- keeping the whole object here is what makes
  // that possible.
  const [userPolicies, setUserPolicies] = useState<Map<string, Policy | null>>(new Map());
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [togglingUserId, setTogglingUserId] = useState<string | null>(null);
  const [deletingUserId, setDeletingUserId] = useState<string | null>(null);
  const [savingGroupUserId, setSavingGroupUserId] = useState<string | null>(null);
  const [savingMfaUserId, setSavingMfaUserId] = useState<string | null>(null);

  async function refreshUsers() {
    setLoadingUsers(true);
    try {
      const [list, groupList] = await Promise.all([
        listTenantUsers(session.tenantId, session.token),
        listGroups(session.tenantId, session.token),
      ]);
      setUsers(list);
      setGroups(groupList);
      const policies = await Promise.all(
        list.map((u) => getPolicy(session.tenantId, "USER", u.id, session.token)),
      );
      const policyMap = new Map<string, Policy | null>();
      list.forEach((u, i) => policyMap.set(u.id, policies[i]));
      setUserPolicies(policyMap);
    } catch {
      // Non-fatal -- the create-user form above still works even if this
      // management list can't load.
    } finally {
      setLoadingUsers(false);
    }
  }

  useEffect(() => {
    void refreshUsers();
    // Only offer the checkbox at all if this tenant actually has Google
    // Workspace configured -- otherwise it's a confusing option that can
    // never do anything (see Settings -> Google Workspace).
    void getGoogleWorkspaceConfig(session.tenantId, session.token)
      .then((config) => setGoogleWorkspaceConfigured(config !== null))
      .catch(() => setGoogleWorkspaceConfigured(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleDelete(userId: string, label: string) {
    if (!window.confirm(`Delete ${label}? This removes them from this platform and, if configured, Google Workspace too. This cannot be undone.`)) {
      return;
    }
    setDeletingUserId(userId);
    setError(null);
    try {
      const result = await deleteUser(session.tenantId, userId, session.token);
      if (result.googleWorkspaceError) {
        setError(`User deleted here, but Google Workspace deletion failed: ${result.googleWorkspaceError}`);
      }
      await refreshUsers();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setDeletingUserId(null);
    }
  }

  // Consolidated per-user management (2026-10-26): group, 2FA override,
  // and "allow any IP" all settable right here on the user they apply to,
  // instead of needing a separate trip to the Groups page to set a group,
  // which previously had no per-user 2FA control of its own at all --
  // only the group-level one existed. Both routes (here, and the Groups
  // page's own assignUserToGroup) write to the exact same backend field,
  // so either one keeps the other in sync.
  async function handleGroupChange(userId: string, groupId: string) {
    setSavingGroupUserId(userId);
    setError(null);
    try {
      await assignUserToGroup(session.tenantId, userId, groupId || null, session.token);
      setUsers((prev) => prev.map((u) => (u.id === userId ? { ...u, groupId: groupId || null } : u)));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSavingGroupUserId(null);
    }
  }

  async function handleMfaChange(userId: string, value: TriState) {
    setSavingMfaUserId(userId);
    setError(null);
    try {
      const existing = userPolicies.get(userId);
      const updated = await putPolicy(
        {
          tenantId: session.tenantId,
          scope: "USER",
          scopeId: userId,
          allowedCidrs: existing?.allowedCidrs ?? null,
          blockedCidrs: existing?.blockedCidrs ?? null,
          allowedCountries: existing?.allowedCountries ?? null,
          blockedCountries: existing?.blockedCountries ?? null,
          mfaRequired: value === "" ? null : value === "true",
        },
        session.token,
      );
      setUserPolicies((prev) => new Map(prev).set(userId, updated));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSavingMfaUserId(null);
    }
  }

  async function toggleAllowAnyIp(userId: string, allow: boolean) {
    setTogglingUserId(userId);
    try {
      const existing = userPolicies.get(userId);
      const updated = await putPolicy(
        {
          tenantId: session.tenantId,
          scope: "USER",
          scopeId: userId,
          // Turning it off clears the override entirely (null), not "set
          // to empty" -- that's what lets this user fall back to
          // inheriting whatever the tenant/group policy says next, rather
          // than permanently pinning an empty allow-list (which would
          // mean "allow nothing" and lock them out completely).
          allowedCidrs: allow ? [ALLOW_ANY_IP] : null,
          blockedCidrs: existing?.blockedCidrs ?? null,
          allowedCountries: existing?.allowedCountries ?? null,
          blockedCountries: existing?.blockedCountries ?? null,
          mfaRequired: existing?.mfaRequired ?? null,
        },
        session.token,
      );
      setUserPolicies((prev) => new Map(prev).set(userId, updated));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setTogglingUserId(null);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!email || !displayName || password.length < 8) {
      setError("Enter an email, display name, and a password of at least 8 characters.");
      return;
    }
    setPending(true);
    try {
      const created = await createUser(
        session.tenantId, email, displayName, password, role, session.token,
        googleWorkspaceConfigured && createInGoogleWorkspace,
      );
      setJustCreated(created);
      setQrDataUrl(await QRCode.toDataURL(created.provisioningUri));
      setEmail("");
      setDisplayName("");
      setPassword("");
      setRole("USER");
      setCreateInGoogleWorkspace(true);
      setShowCreate(false);
      await refreshUsers();
    } catch (err) {
      if (err instanceof UpstreamError && err.status === 409) {
        setError("A user with that email already exists.");
      } else {
        setError(errorMessage(err));
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <main className="page">
      <PageHeader
        title="Users"
        subtitle="Create accounts and manage each person's group, two-factor requirement, and IP access in one place."
        actions={
          <button type="button" onClick={() => setShowCreate((v) => !v)}>
            {showCreate ? "Cancel" : "+ Add user"}
          </button>
        }
      />

      {error && <Alert kind="error">{error}</Alert>}

      {justCreated && qrDataUrl && (
        <div className="card card--padded" style={{ marginBottom: 24 }}>
          <h3 className="card__title">
            {justCreated.displayName} <StatusBadge tone="success">Created</StatusBadge>
          </h3>
          <p className="card__desc">
            {justCreated.email} was created as {justCreated.role}. Share the password with them directly (shown once,
            not stored for retrieval). They also need this authenticator QR code to sign in, since every login
            requires a second factor. Scan it now, before this screen is closed.
          </p>
          <div className="qr-wrap">
            <img src={qrDataUrl} alt="TOTP QR code" width={180} height={180} />
          </div>
          <p className="hint">
            Can't scan right now? Manual key (time-based): <code>{justCreated.totpSecret}</code>
          </p>
          <p className="hint">They can enroll additional or replacement devices later on the "My Security" page.</p>
          {justCreated.googleWorkspaceProvisioned && (
            <Alert kind="success">Also created in Google Workspace. No separate Google password is needed to sign in.</Alert>
          )}
          {justCreated.googleWorkspaceError && (
            <Alert kind="error">Google Workspace account creation failed: {justCreated.googleWorkspaceError}</Alert>
          )}
          <div className="form-actions">
            <button type="button" className="btn-secondary" onClick={() => setJustCreated(null)}>
              Done
            </button>
          </div>
        </div>
      )}

      {showCreate && (
        <form className="card card--padded" style={{ marginBottom: 24 }} onSubmit={(e) => void handleCreate(e)}>
          <h3 className="card__title">New user</h3>
          <p className="card__desc">They'll sign in with these credentials plus an authenticator app.</p>

          <div className="form-grid">
            <label className="login-form__field">
              Email
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </label>

            <label className="login-form__field">
              Display name
              <input type="text" value={displayName} onChange={(e) => setDisplayName(e.target.value)} required />
            </label>

            <label className="login-form__field">
              Temporary password
              <input
                type="text"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={8}
                placeholder="At least 8 characters"
              />
            </label>

            <label className="login-form__field">
              Role
              <select value={role} onChange={(e) => setRole(e.target.value as "ADMIN" | "USER")}>
                <option value="USER">User</option>
                <option value="ADMIN">Admin</option>
              </select>
            </label>
          </div>

          {googleWorkspaceConfigured && (
            <label className="checkbox-field" style={{ marginTop: 16 }}>
              <input
                type="checkbox"
                checked={createInGoogleWorkspace}
                onChange={(e) => setCreateInGoogleWorkspace(e.target.checked)}
              />
              Also create this user in Google Workspace
            </label>
          )}

          <div className="form-actions">
            <button type="button" className="btn-secondary" onClick={() => setShowCreate(false)} disabled={pending}>
              Cancel
            </button>
            <button type="submit" disabled={pending}>
              <PendingLabel pending={pending} idle="Create user" busy="Creating…" />
            </button>
          </div>
        </form>
      )}

      <div className="section-title">
        <h2>All users {!loadingUsers && <span className="hint">({users.length})</span>}</h2>
      </div>
      <p className="hint" style={{ marginTop: 0 }}>
        "Allow from any IP" exempts a user from every IP restriction (tenant or group policy), useful to unblock
        someone who is locked out. It has no effect if the tenant policy marks that setting as a hard cap.
      </p>

      {loadingUsers ? (
        <SkeletonRows rows={5} />
      ) : users.length === 0 ? (
        <EmptyState
          title="No users yet"
          description="Add your first user to get started."
          action={
            <button type="button" onClick={() => setShowCreate(true)}>
              + Add user
            </button>
          }
        />
      ) : (
        <div className="card table-card">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Status</th>
                <th>Group</th>
                <th>2FA</th>
                <th>Any IP</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const mfaValue: TriState =
                  userPolicies.get(u.id)?.mfaRequired === null || userPolicies.get(u.id)?.mfaRequired === undefined
                    ? ""
                    : userPolicies.get(u.id)!.mfaRequired
                      ? "true"
                      : "false";
                const anyIpAllowed = userPolicies.get(u.id)?.allowedCidrs?.includes(ALLOW_ANY_IP) ?? false;
                return (
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
                      <StatusBadge tone={u.role === "ADMIN" ? "info" : "neutral"}>{u.role}</StatusBadge>
                    </td>
                    <td>
                      <StatusBadge tone={u.status === "ACTIVE" ? "success" : "warning"}>
                        {u.status === "ACTIVE" ? "Active" : "Suspended"}
                      </StatusBadge>
                    </td>
                    <td>
                      <select
                        value={u.groupId ?? ""}
                        disabled={savingGroupUserId === u.id}
                        onChange={(e) => void handleGroupChange(u.id, e.target.value)}
                      >
                        <option value="">No group</option>
                        {groups.map((g) => (
                          <option key={g.id} value={g.id}>
                            {g.name}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <select
                        value={mfaValue}
                        disabled={savingMfaUserId === u.id}
                        onChange={(e) => void handleMfaChange(u.id, e.target.value as TriState)}
                      >
                        <option value="">Inherit</option>
                        <option value="true">Required</option>
                        <option value="false">Not required</option>
                      </select>
                    </td>
                    <td>
                      <label className="checkbox-field">
                        <input
                          type="checkbox"
                          checked={anyIpAllowed}
                          disabled={togglingUserId === u.id}
                          onChange={(e) => void toggleAllowAnyIp(u.id, e.target.checked)}
                        />
                        {anyIpAllowed ? "Allowed" : "Restricted"}
                      </label>
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          type="button"
                          className="btn-danger btn-sm"
                          disabled={deletingUserId === u.id}
                          onClick={() => void handleDelete(u.id, `${u.displayName} (${u.email})`)}
                        >
                          <PendingLabel pending={deletingUserId === u.id} idle="Delete" busy="Deleting…" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </main>
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
