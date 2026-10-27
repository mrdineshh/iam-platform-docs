import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listTenantUsers, impersonate, type AdminUserListEntry } from "@/lib/impersonate";
import { loadSession, startImpersonation } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import {
  Alert,
  Avatar,
  EmptyState,
  PageHeader,
  Pagination,
  PendingLabel,
  SkeletonRows,
  SortableTh,
  StatusBadge,
  TableToolbar,
} from "@/components/ui";
import { useTable } from "@/lib/useTable";

/**
 * Admin-only "Switch to user" picker. Every switch is server-side audited
 * (iam-tenant-svc's ImpersonateController publishes identity.impersonated)
 * -- this page is just the UI, the real guard and the audit trail live on
 * the backend, not here.
 */
export function SwitchUserPage() {
  const session = loadSession()!;
  const navigate = useNavigate();
  const [users, setUsers] = useState<AdminUserListEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [switching, setSwitching] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      setLoading(true);
      setError(null);
      try {
        setUsers(await listTenantUsers(session.tenantId, session.token));
      } catch (err) {
        setError(errorMessage(err));
      } finally {
        setLoading(false);
      }
      // eslint-disable-next-line react-hooks/exhaustive-deps
    })();
  }, []);

  async function handleSwitch(userId: string) {
    setError(null);
    setSwitching(userId);
    try {
      const result = await impersonate(session.tenantId, userId, session.token);
      startImpersonation({
        token: result.token,
        role: result.role,
        tenantId: session.tenantId,
        tenantName: session.tenantName,
        email: result.email,
        displayName: result.displayName,
      });
      navigate("/");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSwitching(null);
    }
  }

  const table = useTable(users, {
    searchText: (u) => `${u.displayName} ${u.email} ${u.role} ${u.status}`,
    sorters: {
      name: (a, b) => a.displayName.localeCompare(b.displayName),
      role: (a, b) => a.role.localeCompare(b.role),
      status: (a, b) => a.status.localeCompare(b.status),
    },
    initialSort: { key: "name", dir: "asc" },
  });

  return (
    <main className="page">
      <PageHeader
        title="Switch to user"
        subtitle="Sign in as another user to see exactly what they see. Every switch is recorded in the audit log."
      />

      {error && <Alert kind="error">{error}</Alert>}

      {loading ? (
        <SkeletonRows rows={4} />
      ) : users.length === 0 ? (
        <EmptyState title="No users yet" description="Create a user first, then you can switch to them here." />
      ) : (
        <>
          <TableToolbar
            query={table.query}
            onQuery={table.setQuery}
            placeholder="Search users"
            summary={`${table.filteredCount} of ${table.total} users`}
          />
          <div className="card table-card">
            <table>
              <thead>
                <tr>
                  <SortableTh label="User" sortKey="name" sort={table.sort} onSort={table.toggleSort} />
                  <SortableTh label="Role" sortKey="role" sort={table.sort} onSort={table.toggleSort} />
                  <SortableTh label="Status" sortKey="status" sort={table.sort} onSort={table.toggleSort} />
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {table.filteredCount === 0 && (
                  <tr className="table-empty-row">
                    <td colSpan={4}>No users match "{table.query}".</td>
                  </tr>
                )}
                {table.pageRows.map((u) => (
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
                      <div className="row-actions">
                        <button
                          type="button"
                          className="btn-secondary btn-sm"
                          disabled={switching === u.id}
                          onClick={() => void handleSwitch(u.id)}
                        >
                          <PendingLabel pending={switching === u.id} idle="Switch to this user" busy="Switching…" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
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

function errorMessage(err: unknown): string {
  if (err instanceof UpstreamError) {
    if (err.status === 401) return "Your session expired. Please sign in again.";
    if (err.status === 403) return "You don't have permission to do this.";
    if (err.status === 404) return "That user could not be found.";
    return "This is temporarily unavailable. Please try again.";
  }
  return "This is temporarily unavailable. Please try again.";
}
