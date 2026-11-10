import { useEffect, useMemo, useState } from "react";
import { getOrganizationalUnits, syncOrganizationalUnit, type OrgUnitReport } from "@/lib/googleWorkspace";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import { Alert, EmptyState, PageHeader, PendingLabel, SkeletonRows, StatusBadge } from "@/components/ui";
import { Icon } from "@/components/icons";
import { useConfirm, useToast } from "@/components/feedback";

/**
 * Read-only, live view of Google Workspace's organizational units and who's in each one -- see
 * GoogleWorkspaceDirectoryReportService's doc comment (iam-tenant-svc). Nothing here is stored in
 * IAM, and nothing in Google is changed by viewing it; the "Refresh" button is the only thing that
 * triggers a call to Google, and it only ever reads.
 */
export function OrganizationalUnitsPage() {
  const session = loadSession()!;
  const confirm = useConfirm();
  const toast = useToast();
  const [report, setReport] = useState<OrgUnitReport[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [syncing, setSyncing] = useState(false);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const data = await getOrganizationalUnits(session.tenantId, session.token);
      setReport(data);
      setSelected((prev) => (prev && data.some((ou) => ou.orgUnitPath === prev) ? prev : (data[0]?.orgUnitPath ?? null)));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // The only action on this page that changes anything -- see GoogleWorkspaceOuProvisioningService's
  // doc comment (iam-tenant-svc) for exactly what it does: existing IAM users get their group updated
  // to match this OU; anyone with no IAM account yet gets one created, a first 2FA device enrolled,
  // pushed to every connected app, and emailed their address, a temporary password and a QR code.
  // Scoped to exactly this one OU -- manual, not automatic; re-run it to catch up with later changes.
  async function handleSync(ou: OrgUnitReport) {
    const suggestedName = ou.orgUnitPath === "/" ? "Root" : ou.orgUnitPath.replace(/^\/+/, "");
    const ok = await confirm({
      title: "Sync and provision this OU?",
      message: (
        <>
          For every person in <strong>{ou.orgUnitPath}</strong>: if they already have an IAM account, their
          group will be set to <strong>{suggestedName}</strong> (created if it doesn't exist) -- replacing
          whatever group they currently have. If they don't have an IAM account yet, one will be created for
          them, with a temporary password and a 2FA QR code emailed to their address. Your IP and app
          restrictions can then be set on that group, from the Groups page.
        </>
      ),
      confirmLabel: "Sync this OU",
      danger: true,
    });
    if (!ok) return;

    setSyncing(true);
    try {
      const result = await syncOrganizationalUnit(session.tenantId, ou.orgUnitPath, session.token);
      const parts = [
        `"${result.groupName}": ${result.matched.length} existing user${result.matched.length === 1 ? "" : "s"} synced`,
      ];
      if (result.created.length > 0) {
        parts.push(`${result.created.length} new account${result.created.length === 1 ? "" : "s"} created and emailed`);
      }
      if (result.createdButEmailFailed.length > 0) {
        toast.error(
          `${parts.join(", ")}. ${result.createdButEmailFailed.length} account${result.createdButEmailFailed.length === 1 ? "" : "s"} ` +
            `created but the email failed to send: ${result.createdButEmailFailed.join(", ")}. Hand them their credentials another way.`,
        );
      } else {
        toast.success(`${parts.join(", ")}.`);
      }
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setSyncing(false);
    }
  }

  const totalUsers = useMemo(() => report?.reduce((n, ou) => n + ou.users.length, 0) ?? 0, [report]);
  const current = report?.find((ou) => ou.orgUnitPath === selected) ?? null;
  const visibleUsers = useMemo(() => {
    if (!current) return [];
    const q = search.trim().toLowerCase();
    if (!q) return current.users;
    return current.users.filter(
      (u) => u.primaryEmail.toLowerCase().includes(q) || (u.fullName ?? "").toLowerCase().includes(q),
    );
  }, [current, search]);

  return (
    <main className="page page--wide">
      <PageHeader
        title="Organizational units"
        subtitle={`A live, read-only view of your Google Workspace directory${report ? ` -- ${report.length} unit${report.length === 1 ? "" : "s"}, ${totalUsers} user${totalUsers === 1 ? "" : "s"}` : ""}. Nothing here is stored in IAM or changed in Google.`}
        actions={
          <button type="button" className="btn-secondary" disabled={loading} onClick={() => void load()}>
            <PendingLabel pending={loading} idle="Refresh" busy="Loading…" />
          </button>
        }
      />

      {error && <Alert kind="error">{error}</Alert>}

      {loading && !report ? (
        <SkeletonRows rows={6} />
      ) : report && report.length === 0 ? (
        <EmptyState title="No users found" description="This Google Workspace domain has no users yet." />
      ) : report ? (
        <div className="ou-browser">
          <aside className="ou-browser__sidebar">
            {report.map((ou) => (
              <button
                key={ou.orgUnitPath}
                type="button"
                className={ou.orgUnitPath === selected ? "ou-browser__unit ou-browser__unit--active" : "ou-browser__unit"}
                onClick={() => setSelected(ou.orgUnitPath)}
              >
                <Icon name="groups" size={16} />
                <span className="ou-browser__unit-name">{ou.orgUnitPath}</span>
                <span className="ou-browser__unit-count">{ou.users.length}</span>
              </button>
            ))}
          </aside>

          <section className="ou-browser__main">
            {current && (
              <>
                <div className="ou-browser__main-head">
                  <h2>{current.orgUnitPath}</h2>
                  <div className="ou-browser__main-actions">
                    <input
                      className="ou-browser__search"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      placeholder="Search name or email…"
                    />
                    <button type="button" className="btn-secondary" disabled={syncing} onClick={() => void handleSync(current)}>
                      <PendingLabel pending={syncing} idle="Sync into IAM group" busy="Syncing…" />
                    </button>
                  </div>
                </div>

                {visibleUsers.length === 0 ? (
                  <EmptyState title="No matching users" description="Try a different search." />
                ) : (
                  <div className="table-card">
                    <table>
                      <thead>
                        <tr>
                          <th>User</th>
                          <th>Email</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {visibleUsers.map((u) => (
                          <tr key={u.primaryEmail}>
                            <td>
                              <div className="cell-user">
                                <span className="avatar">{(u.fullName ?? u.primaryEmail).charAt(0).toUpperCase()}</span>
                                <span className="cell-user__name">{u.fullName ?? "—"}</span>
                              </div>
                            </td>
                            <td>{u.primaryEmail}</td>
                            <td>
                              <StatusBadge tone={u.suspended ? "warning" : "success"}>
                                {u.suspended ? "Suspended" : "Active"}
                              </StatusBadge>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </section>
        </div>
      ) : null}
    </main>
  );
}

function errorMessage(err: unknown): string {
  if (err instanceof UpstreamError) {
    if (err.status === 401) return "Your session expired. Please sign in again.";
    if (err.status === 403) return "You don't have permission to view this.";
    if (err.status === 404) return "Google Workspace isn't connected for this tenant yet.";
    return "This is temporarily unavailable. Please try again.";
  }
  return "This is temporarily unavailable. Please try again.";
}
