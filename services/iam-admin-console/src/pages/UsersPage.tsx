import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { createUser, type CreatedUser } from "@/lib/identity";
import { listTenantUsers, type AdminUserListEntry } from "@/lib/impersonate";
import { getPolicy, putPolicy } from "@/lib/policy";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";

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
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [justCreated, setJustCreated] = useState<CreatedUser | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);

  const [users, setUsers] = useState<AdminUserListEntry[]>([]);
  const [anyIpUserIds, setAnyIpUserIds] = useState<Set<string>>(new Set());
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [togglingUserId, setTogglingUserId] = useState<string | null>(null);

  async function refreshUsers() {
    setLoadingUsers(true);
    try {
      const list = await listTenantUsers(session.tenantId, session.token);
      setUsers(list);
      const flagged = await Promise.all(
        list.map(async (u) => {
          const policy = await getPolicy(session.tenantId, "USER", u.id, session.token);
          return policy?.allowedCidrs?.includes(ALLOW_ANY_IP) ? u.id : null;
        }),
      );
      setAnyIpUserIds(new Set(flagged.filter((id): id is string => id !== null)));
    } catch {
      // Non-fatal -- the create-user form above still works even if this
      // management list can't load.
    } finally {
      setLoadingUsers(false);
    }
  }

  useEffect(() => {
    void refreshUsers();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function toggleAllowAnyIp(userId: string, allow: boolean) {
    setTogglingUserId(userId);
    try {
      await putPolicy(
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
        },
        session.token,
      );
      setAnyIpUserIds((prev) => {
        const next = new Set(prev);
        if (allow) next.add(userId);
        else next.delete(userId);
        return next;
      });
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
      const created = await createUser(session.tenantId, email, displayName, password, role, session.token);
      setJustCreated(created);
      setQrDataUrl(await QRCode.toDataURL(created.provisioningUri));
      setEmail("");
      setDisplayName("");
      setPassword("");
      setRole("USER");
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
      <h1>Users</h1>

      {error && (
        <p role="alert" className="login-form__error">
          {error}
        </p>
      )}

      {justCreated && qrDataUrl && (
        <div className="callout">
          <strong>{justCreated.displayName}</strong> ({justCreated.email}) created as {justCreated.role}.
          <p>
            Share the password with them directly (shown once, not stored anywhere for retrieval). They also need
            this authenticator QR code to sign in at all — every login requires a second factor, so scan it now,
            before this screen is closed:
          </p>
          <div className="qr-wrap">
            <img src={qrDataUrl} alt="TOTP QR code" width={180} height={180} />
          </div>
          <p>
            Can't scan right now? Manual key (time-based): <code>{justCreated.totpSecret}</code>
          </p>
          <p>They can enroll additional/replacement devices themselves later on the "My Security" page.</p>
        </div>
      )}

      <form className="login-form" onSubmit={(e) => void handleCreate(e)}>
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

        <div className="login-form__buttons">
          <button type="submit" disabled={pending}>
            {pending ? "Creating…" : "Create user"}
          </button>
        </div>
      </form>

      <h2>Manage users</h2>
      <p className="hint">
        "Allow sign-in from any IP" exempts a specific user from every IP restriction (tenant or group policy) --
        use it to unblock someone who's locked out, or for an account that needs to sign in from anywhere (e.g. a
        traveling admin). It doesn't apply if the tenant policy marks IP restrictions as a hard cap, which is
        designed to allow no exceptions at all.
      </p>
      {loadingUsers ? (
        <p>Loading…</p>
      ) : users.length === 0 ? (
        <p>No users yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Allow sign-in from any IP</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.displayName}</td>
                <td>{u.email}</td>
                <td>{u.role}</td>
                <td>
                  <label className="checkbox-field">
                    <input
                      type="checkbox"
                      checked={anyIpUserIds.has(u.id)}
                      disabled={togglingUserId === u.id}
                      onChange={(e) => void toggleAllowAnyIp(u.id, e.target.checked)}
                    />
                    {anyIpUserIds.has(u.id) ? "Allowed from anywhere" : "Restricted"}
                  </label>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
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
