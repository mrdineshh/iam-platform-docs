import { useEffect, useState } from "react";
import {
  approveDevice, listDevices, rejectDevice, revokeDevice, suspendDevice, type DeviceSummary,
} from "@/lib/devices";
import { listTenantUsers, type AdminUserListEntry } from "@/lib/impersonate";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import { Alert, EmptyState, PageHeader, PendingLabel, SkeletonRows, StatusBadge } from "@/components/ui";
import { useConfirm, useToast } from "@/components/feedback";

/**
 * Endpoint Device Trust spec Section 13 ("Endpoint Security dashboard" +
 * "Device inventory and detail"). Windows-only Phase 1 -- the platform
 * column only ever shows WINDOWS today (DevicePlatform enum, iam-tenant-svc),
 * but the table doesn't hardcode that assumption anywhere a future macOS/
 * Ubuntu agent would need a frontend change here too.
 */
export function EndpointDevicesPage() {
  const session = loadSession()!;
  const confirm = useConfirm();
  const toast = useToast();
  const [devices, setDevices] = useState<DeviceSummary[] | null>(null);
  const [users, setUsers] = useState<Record<string, AdminUserListEntry>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actingOn, setActingOn] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const [deviceList, userList] = await Promise.all([
        listDevices(session.tenantId, session.token),
        listTenantUsers(session.tenantId, session.token),
      ]);
      setDevices(deviceList);
      setUsers(Object.fromEntries(userList.map((u) => [u.id, u])));
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

  async function handleApprove(device: DeviceSummary) {
    setActingOn(device.id);
    try {
      await approveDevice(session.tenantId, device.id, session.token);
      toast.success(`${deviceLabel(device)} approved. It can now satisfy device-trust requirements during sign-in.`);
      await load();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setActingOn(null);
    }
  }

  async function handleReject(device: DeviceSummary) {
    const ok = await confirm({
      title: "Reject this device?",
      message: <>{deviceLabel(device)} will not be able to satisfy device-trust requirements. It can re-enroll later.</>,
      confirmLabel: "Reject device",
      danger: true,
    });
    if (!ok) return;
    setActingOn(device.id);
    try {
      await rejectDevice(session.tenantId, device.id, session.token);
      toast.success(`${deviceLabel(device)} rejected.`);
      await load();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setActingOn(null);
    }
  }

  async function handleSuspend(device: DeviceSummary) {
    const ok = await confirm({
      title: "Suspend this device?",
      message: <>{deviceLabel(device)} will immediately stop satisfying device-trust requirements, on its very next request. This can be reversed by approving it again.</>,
      confirmLabel: "Suspend device",
      danger: true,
    });
    if (!ok) return;
    setActingOn(device.id);
    try {
      await suspendDevice(session.tenantId, device.id, session.token);
      toast.success(`${deviceLabel(device)} suspended.`);
      await load();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setActingOn(null);
    }
  }

  async function handleRevoke(device: DeviceSummary) {
    const ok = await confirm({
      title: "Revoke this device?",
      message: (
        <>
          This permanently revokes trust for {deviceLabel(device)}. Its certificate is revoked immediately, and any
          session currently using this device will be cut off on its very next request. This cannot be undone --
          the device would need to enroll again from scratch.
        </>
      ),
      confirmLabel: "Revoke device",
      danger: true,
    });
    if (!ok) return;
    setActingOn(device.id);
    try {
      await revokeDevice(session.tenantId, device.id, session.token);
      toast.success(`${deviceLabel(device)} revoked.`);
      await load();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setActingOn(null);
    }
  }

  const pendingCount = devices?.filter((d) => d.lifecycleStatus === "PENDING_APPROVAL").length ?? 0;

  return (
    <main className="page page--wide">
      <PageHeader
        title="Endpoint Security"
        subtitle={`Devices registered through the IAM endpoint agent${devices ? ` -- ${devices.length} total${pendingCount > 0 ? `, ${pendingCount} awaiting approval` : ""}` : ""}. Windows only in this phase.`}
        actions={
          <button type="button" className="btn-secondary" disabled={loading} onClick={() => void load()}>
            <PendingLabel pending={loading} idle="Refresh" busy="Loading…" />
          </button>
        }
      />

      {error && <Alert kind="error">{error}</Alert>}

      {loading && !devices ? (
        <SkeletonRows rows={6} />
      ) : devices && devices.length === 0 ? (
        <EmptyState
          title="No devices registered yet"
          description="Devices appear here once a user installs the endpoint agent and enrolls."
        />
      ) : devices ? (
        <div className="table-card">
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>User</th>
                <th>Ownership</th>
                <th>Status</th>
                <th>Compliance</th>
                <th>Certificate</th>
                <th>Last seen</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.id}>
                  <td>
                    <div className="cell-user">
                      <span className="avatar">{(d.hostname ?? d.platform).charAt(0).toUpperCase()}</span>
                      <span className="cell-user__name">{d.hostname ?? "(unnamed)"}</span>
                    </div>
                  </td>
                  <td>{users[d.userId]?.email ?? d.userId}</td>
                  <td>{d.ownership === "CORPORATE" ? "Corporate" : "BYOD"}</td>
                  <td><StatusBadge tone={statusTone(d.lifecycleStatus)}>{statusLabel(d.lifecycleStatus)}</StatusBadge></td>
                  <td>
                    {d.postureStatus ? (
                      <StatusBadge tone={d.postureStatus === "COMPLIANT" ? "success" : d.postureStatus === "NON_COMPLIANT" ? "danger" : "neutral"}>
                        {d.postureStatus === "COMPLIANT" ? "Compliant" : d.postureStatus === "NON_COMPLIANT" ? "Non-compliant" : "Unknown"}
                      </StatusBadge>
                    ) : "—"}
                  </td>
                  <td>{d.certificateStatus ? <StatusBadge tone={d.certificateStatus === "ACTIVE" ? "success" : "neutral"}>{d.certificateStatus}</StatusBadge> : "—"}</td>
                  <td>{d.lastSeenAt ? new Date(d.lastSeenAt).toLocaleString() : "Never"}</td>
                  <td>
                    <div className="row-actions">
                      {d.lifecycleStatus === "PENDING_APPROVAL" && (
                        <>
                          <button type="button" className="btn-sm" disabled={actingOn === d.id} onClick={() => void handleApprove(d)}>
                            Approve
                          </button>
                          <button type="button" className="btn-danger btn-sm" disabled={actingOn === d.id} onClick={() => void handleReject(d)}>
                            Reject
                          </button>
                        </>
                      )}
                      {(d.lifecycleStatus === "APPROVED" || d.lifecycleStatus === "NON_COMPLIANT") && (
                        <button type="button" className="btn-secondary btn-sm" disabled={actingOn === d.id} onClick={() => void handleSuspend(d)}>
                          Suspend
                        </button>
                      )}
                      {d.lifecycleStatus === "SUSPENDED" && (
                        <button type="button" className="btn-sm" disabled={actingOn === d.id} onClick={() => void handleApprove(d)}>
                          Reactivate
                        </button>
                      )}
                      {!["REVOKED", "REJECTED", "DECOMMISSIONED"].includes(d.lifecycleStatus) && (
                        <button type="button" className="btn-danger btn-sm" disabled={actingOn === d.id} onClick={() => void handleRevoke(d)}>
                          Revoke
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </main>
  );
}

function deviceLabel(d: DeviceSummary): string {
  return d.hostname ? `"${d.hostname}"` : `this device`;
}

function statusLabel(status: DeviceSummary["lifecycleStatus"]): string {
  switch (status) {
    case "PENDING_APPROVAL": return "Pending approval";
    case "NON_COMPLIANT": return "Non-compliant";
    case "AUTHENTICATION_PENDING": return "Authenticating";
    default: return status.charAt(0) + status.slice(1).toLowerCase();
  }
}

function statusTone(status: DeviceSummary["lifecycleStatus"]): "success" | "warning" | "danger" | "neutral" | "info" {
  switch (status) {
    case "APPROVED": return "success";
    case "PENDING_APPROVAL":
    case "AUTHENTICATION_PENDING":
      return "info";
    case "NON_COMPLIANT":
    case "SUSPENDED":
      return "warning";
    case "REJECTED":
    case "REVOKED":
      return "danger";
    default: return "neutral";
  }
}

function errorMessage(err: unknown): string {
  if (err instanceof UpstreamError) {
    if (err.status === 401) return "Your session expired. Please sign in again.";
    if (err.status === 403) return "You don't have permission to do this.";
    if (err.status === 404) return "That device could not be found.";
    return "This is temporarily unavailable. Please try again.";
  }
  return "This is temporarily unavailable. Please try again.";
}
