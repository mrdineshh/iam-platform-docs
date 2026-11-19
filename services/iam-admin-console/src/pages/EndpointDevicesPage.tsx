import { Fragment, useEffect, useRef, useState } from "react";
import {
  approveDevice, decommissionDevice, getLoginRule, grantComplianceException, listDeviceEvents, removeComplianceException, setLoginRule, listDevices, rejectDevice, revokeDevice, suspendDevice, type DeviceEvent, type DeviceSummary, type PostureSignals,
} from "@/lib/devices";
import { listTenantUsers, type AdminUserListEntry } from "@/lib/impersonate";
import { loadSession } from "@/lib/session";
import { UpstreamError } from "@/lib/http";
import { Alert, EmptyState, PageHeader, PendingLabel, SkeletonRows, StatusBadge, TableToolbar } from "@/components/ui";
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
  const [allDevices, setAllDevices] = useState<DeviceSummary[] | null>(null);
  const [showRemoved, setShowRemoved] = useState(false);
  const [users, setUsers] = useState<Record<string, AdminUserListEntry>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actingOn, setActingOn] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<FleetFilter>("ALL");
  const [query, setQuery] = useState("");
  const [showGuide, setShowGuide] = useState(false);
  const [exceptionFor, setExceptionFor] = useState<DeviceSummary | null>(null);
  const [loginRule, setLoginRuleState] = useState<boolean | null>(null);
  const [savingRule, setSavingRule] = useState(false);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const [deviceList, userList, rule] = await Promise.all([
        listDevices(session.tenantId, session.token),
        listTenantUsers(session.tenantId, session.token),
        getLoginRule(session.tenantId, session.token),
      ]);
      setLoginRuleState(rule);
      setAllDevices(deviceList);
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

  useEffect(() => {
    const timer = window.setInterval(() => void load(), 30_000);
    return () => window.clearInterval(timer);
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

  // Active non-admin users who own no approved laptop: the people who could no longer sign in the moment the rule is on.
  function usersWithoutApprovedLaptop(): AdminUserListEntry[] {
    const hasApproved = new Set((allDevices ?? []).filter((d) => d.lifecycleStatus === "APPROVED").map((d) => d.userId));
    return Object.values(users).filter((u) => u.role === "USER" && u.status === "ACTIVE" && !hasApproved.has(u.id));
  }

  async function handleToggleLoginRule(next: boolean) {
    if (next) {
      const locked = usersWithoutApprovedLaptop();
      const ok = await confirm({
        title: "Require an authorised laptop to sign in?",
        message: (
          <>
            From now on, people who are not administrators can only sign in from a laptop that is approved and passes the
            security checks. Anyone else is told at the sign-in screen that they are not authorised, and is not signed in.
            Administrators are never affected, and registering a new laptop is always allowed.
            {locked.length > 0 ? (
              <>
                {" "}<strong>{locked.length} active user{locked.length === 1 ? " has" : "s have"} no approved laptop yet and could not sign in:</strong>{" "}
                {locked.slice(0, 8).map((u) => u.email).join(", ")}{locked.length > 8 ? `, and ${locked.length - 8} more` : ""}.
              </>
            ) : null}
          </>
        ),
        confirmLabel: "Turn on",
        danger: true,
      });
      if (!ok) return;
    }
    setSavingRule(true);
    try {
      await setLoginRule(session.tenantId, next, session.token);
      setLoginRuleState(next);
      toast.success(next ? "Sign-in now requires an authorised laptop (administrators excepted)." : "Sign-in no longer requires an authorised laptop.");
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setSavingRule(false);
    }
  }

  async function handleGrantException(device: DeviceSummary, days: number, reason: string) {
    setActingOn(device.id);
    try {
      await grantComplianceException(session.tenantId, device.id, days, reason, session.token);
      toast.success(`${deviceLabel(device)} may now open protected apps for ${days} day${days === 1 ? "" : "s"}, even though it fails security checks.`);
      setExceptionFor(null);
      await load();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setActingOn(null);
    }
  }

  async function handleEndException(device: DeviceSummary) {
    const ok = await confirm({
      title: "End this exception?",
      message: <>{deviceLabel(device)} will be held to the security checks again straight away.</>,
      confirmLabel: "End exception",
      danger: true,
    });
    if (!ok) return;
    setActingOn(device.id);
    try {
      await removeComplianceException(session.tenantId, device.id, session.token);
      toast.success("Exception ended.");
      await load();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setActingOn(null);
    }
  }

  async function handleRemove(device: DeviceSummary) {
    const ok = await confirm({
      title: "Remove this device?",
      message: (
        <>
          <strong>{deviceLabel(device)}</strong> is taken out of service: its certificate is revoked and it can no
          longer be used to reach protected apps. Nothing is deleted -- its history stays on record (tick "Show removed
          devices" to see it). To register the laptop again afterwards, run <code>--reset-enrollment --confirm</code>{" "}
          on it, then enrol and approve it as a new device.
        </>
      ),
      confirmLabel: "Remove device",
      danger: true,
    });
    if (!ok) return;
    setActingOn(device.id);
    try {
      await decommissionDevice(session.tenantId, device.id, session.token);
      toast.success(`${deviceLabel(device)} removed. Its history is kept.`);
      await load();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setActingOn(null);
    }
  }

  // Removed (decommissioned) devices stay on record but are hidden from the working list unless asked for.
  const removedCount = allDevices?.filter((d) => d.lifecycleStatus === "DECOMMISSIONED").length ?? 0;
  const devices = allDevices && (showRemoved ? allDevices : allDevices.filter((d) => d.lifecycleStatus !== "DECOMMISSIONED"));

  const pendingCount = devices?.filter((d) => d.lifecycleStatus === "PENDING_APPROVAL").length ?? 0;
  const now = Date.now();
  const counts = fleetCounts(devices ?? [], now);
  const needle = query.trim().toLowerCase();
  const visible = (devices ?? []).filter(
    (d) =>
      matchesFilter(d, filter, now) &&
      (!needle || (d.hostname ?? "").toLowerCase().includes(needle) || (users[d.userId]?.email ?? "").toLowerCase().includes(needle)),
  );

  return (
    <main className="page page--wide">
      <PageHeader
        title="Endpoint Security"
        subtitle={`Devices registered through the IAM endpoint agent${devices ? ` -- ${devices.length} total${pendingCount > 0 ? `, ${pendingCount} awaiting approval` : ""}` : ""}. Windows only in this phase.`}
        actions={
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {removedCount > 0 && (
              <label className="checkbox-field">
                <input type="checkbox" checked={showRemoved} onChange={(e) => setShowRemoved(e.target.checked)} />
                Show removed devices ({removedCount})
              </label>
            )}
            <button type="button" className="btn-secondary" onClick={() => setShowGuide(true)}>
              Install / Uninstall Guide
            </button>
            <button type="button" className="btn-secondary" disabled={loading} onClick={() => void load()}>
              <PendingLabel pending={loading} idle="Refresh" busy="Loading…" />
            </button>
          </div>
        }
      />

      {error && <Alert kind="error">{error}</Alert>}

      {loginRule !== null && (
        <div className="table-card" style={{ padding: "14px 18px", marginBottom: 14 }}>
          <label className="checkbox-field">
            <input
              type="checkbox"
              checked={loginRule}
              disabled={savingRule}
              onChange={(e) => void handleToggleLoginRule(e.target.checked)}
            />
            <strong>Only allow sign-in from an approved, compliant laptop</strong>
            {loginRule && <StatusBadge tone="warning">On</StatusBadge>}
          </label>
          <p className="posture-panel__muted" style={{ margin: "6px 0 0" }}>
            Platform-wide, at the sign-in screen (apps can still ask for more). People who are not administrators are told
            "You are not authorised to sign in from this device" and are not signed in. Administrators are never affected,
            so a broken laptop cannot lock you out of this console, and registering a new laptop is always allowed. Off by default.
          </p>
        </div>
      )}

      {loading && !devices ? (
        <SkeletonRows rows={6} />
      ) : devices && devices.length === 0 ? (
        <EmptyState
          title="No devices registered yet"
          description="Devices appear here once a user installs the endpoint agent and enrolls."
        />
      ) : devices ? (
        <>
        <div className="fleet-summary">
          {FLEET_CARDS.map((c) => (
            <button
              key={c.key}
              type="button"
              className={`fleet-card fleet-card--${c.tone}${filter === c.key ? " fleet-card--active" : ""}`}
              onClick={() => setFilter(filter === c.key && c.key !== "ALL" ? "ALL" : c.key)}
            >
              <span className="fleet-card__value">{counts[c.key]}</span>
              <span className="fleet-card__label">{c.label}</span>
            </button>
          ))}
        </div>
        <TableToolbar
          query={query}
          onQuery={setQuery}
          placeholder="Search by device name or user"
          summary={visible.length === devices.length ? undefined : `${visible.length} of ${devices.length} shown`}
        />
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
              {visible.map((d) => (
                <Fragment key={d.id}>
                <tr>
                  <td>
                    <div className="cell-user">
                      <span className="avatar">{(d.hostname ?? d.platform).charAt(0).toUpperCase()}</span>
                      <span className="cell-user__details">
                        <span className="cell-user__name">{d.hostname ?? "(unnamed)"}</span>
                        <span className="cell-user__id" title="Device ID — matches agent --status and Windows Event Log">{d.id}</span>
                      </span>
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
                    {d.complianceExceptionUntil && (
                      <div className="posture-panel__muted" title={d.complianceExceptionReason ?? undefined}>
                        Exception until {new Date(d.complianceExceptionUntil).toLocaleDateString()}
                      </div>
                    )}
                  </td>
                  <td>{d.certificateStatus ? <StatusBadge tone={d.certificateStatus === "ACTIVE" ? "success" : "neutral"}>{d.certificateStatus}</StatusBadge> : "—"}</td>
                  <td>
                    {d.lastSeenAt ? new Date(d.lastSeenAt).toLocaleString() : "Never"}
                    {isOffline(d, now) && <> <StatusBadge tone="danger">Offline</StatusBadge></>}
                  </td>
                  <td>
                    <div className="row-actions">
                      <button type="button" className="btn-secondary btn-sm" onClick={() => setExpandedId(expandedId === d.id ? null : d.id)}>
                        {expandedId === d.id ? "Hide details" : "Details"}
                      </button>
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
                      {(d.lifecycleStatus === "APPROVED" || d.lifecycleStatus === "NON_COMPLIANT") && !d.complianceExceptionUntil && (
                        <button type="button" className="btn-secondary btn-sm" disabled={actingOn === d.id} onClick={() => setExceptionFor(d)}>
                          Allow despite failed checks
                        </button>
                      )}
                      {d.complianceExceptionUntil && (
                        <button type="button" className="btn-secondary btn-sm" disabled={actingOn === d.id} onClick={() => void handleEndException(d)}>
                          End exception
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
                      {d.lifecycleStatus !== "DECOMMISSIONED" && (
                        <button type="button" className="btn-secondary btn-sm" disabled={actingOn === d.id} onClick={() => void handleRemove(d)}>
                          Remove
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
                {expandedId === d.id && (
                  <tr className="posture-row">
                    <td colSpan={8}>
                      <DeviceIdPanel device={d} />
                      <PosturePanel device={d} />
                      <ActivityPanel device={d} users={users} />
                    </td>
                  </tr>
                )}
                </Fragment>
              ))}
            </tbody>
          </table>
          {visible.length === 0 && <p className="posture-panel__empty fleet-empty">No devices match this filter.</p>}
        </div>
        </>
      ) : null}
      {showGuide && <InstallGuideModal onClose={() => setShowGuide(false)} />}
      {exceptionFor && (
        <ComplianceExceptionDialog
          device={exceptionFor}
          busy={actingOn === exceptionFor.id}
          onCancel={() => setExceptionFor(null)}
          onGrant={(days, reason) => void handleGrantException(exceptionFor, days, reason)}
        />
      )}
    </main>
  );
}

type FleetFilter = "ALL" | "APPROVED" | "PENDING" | "NONCOMPLIANT" | "OFFLINE";

const FLEET_CARDS: { key: FleetFilter; label: string; tone: "neutral" | "success" | "warning" | "danger" }[] = [
  { key: "ALL", label: "Devices", tone: "neutral" },
  { key: "APPROVED", label: "Approved", tone: "success" },
  { key: "PENDING", label: "Awaiting approval", tone: "warning" },
  { key: "NONCOMPLIANT", label: "Non-compliant", tone: "danger" },
  { key: "OFFLINE", label: "Offline", tone: "danger" },
];

/** An agent that has not reported for this long is shown as Offline (the default heartbeat is 5 minutes). */
const OFFLINE_AFTER_MS = 15 * 60 * 1000;

function isOffline(d: DeviceSummary, now: number): boolean {
  if (!d.lastSeenAt) return false;
  if (["REVOKED", "REJECTED", "DECOMMISSIONED"].includes(d.lifecycleStatus)) return false;
  return now - new Date(d.lastSeenAt).getTime() > OFFLINE_AFTER_MS;
}

function matchesFilter(d: DeviceSummary, filter: FleetFilter, now: number): boolean {
  switch (filter) {
    case "APPROVED": return d.lifecycleStatus === "APPROVED";
    case "PENDING": return d.lifecycleStatus === "PENDING_APPROVAL";
    case "NONCOMPLIANT": return d.postureStatus === "NON_COMPLIANT";
    case "OFFLINE": return isOffline(d, now);
    default: return true;
  }
}

function fleetCounts(devices: DeviceSummary[], now: number): Record<FleetFilter, number> {
  const count = (f: FleetFilter) => devices.filter((d) => matchesFilter(d, f, now)).length;
  return { ALL: devices.length, APPROVED: count("APPROVED"), PENDING: count("PENDING"), NONCOMPLIANT: count("NONCOMPLIANT"), OFFLINE: count("OFFLINE") };
}

const EVENT_LABELS: Record<string, string> = {
  "device.enrollment.submitted": "Device enrolled",
  "device.approved": "Approved by an admin",
  "device.rejected": "Rejected by an admin",
  "device.suspended": "Suspended by an admin",
  "device.revoked": "Revoked by an admin",
  "device.decommissioned": "Removed from service by an admin",
  "device.compliance_exception.granted": "Allowed despite failed security checks (exception granted)",
  "device.compliance_exception.removed": "Security-check exception ended",
  "device.noncompliant": "Became non-compliant",
  "device.posture_enforced": "Suspended automatically (non-compliant)",
  "device.posture_restored": "Restored (compliant again)",
  "device.certificate.issued": "Certificate issued",
  "device.tampering": "Tampering reported",
  "agent.tamper_detected": "Agent files were changed (tamper detected)",
  "agent.tamper_cleared": "Agent files restored (tamper cleared)",
  "agent.policy_rejected": "A policy was rejected by the agent",
  "agent.clock_moved_backwards": "Device clock moved backwards",
  "agent.posture_collection_failed": "Posture check failed to run",
};

function eventDetail(e: DeviceEvent, users: Record<string, AdminUserListEntry>): string {
  if (!e.metadataJson) return "";
  try {
    const m = JSON.parse(e.metadataJson) as { actor?: string; reason?: string | string[] | null };
    const parts: string[] = [];
    if (m.actor) parts.push(`by ${users[m.actor]?.email ?? m.actor}`);
    if (Array.isArray(m.reason)) parts.push(m.reason.join("; "));
    else if (m.reason) parts.push(String(m.reason));
    return parts.join(" · ");
  } catch {
    return "";
  }
}

function ActivityPanel({ device, users }: { device: DeviceSummary; users: Record<string, AdminUserListEntry> }) {
  const [events, setEvents] = useState<DeviceEvent[] | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const session = loadSession();
    if (!session) return;
    let cancelled = false;
    listDeviceEvents(session.tenantId, device.id, session.token)
      .then((list) => !cancelled && setEvents(list))
      .catch(() => !cancelled && setFailed(true));
    return () => {
      cancelled = true;
    };
  }, [device.id, device.lastSeenAt]);

  return (
    <div className="posture-panel activity-panel">
      <strong>Activity</strong>
      {failed ? (
        <p className="posture-panel__empty">The activity list could not be loaded.</p>
      ) : events === null ? (
        <p className="posture-panel__empty">Loading...</p>
      ) : events.length === 0 ? (
        <p className="posture-panel__empty">No activity recorded yet.</p>
      ) : (
        <ul className="activity-list">
          {events.map((e, i) => (
            <li key={`${e.occurredAt}-${i}`} className="activity-list__item">
              <StatusBadge tone={e.severity === "CRITICAL" ? "danger" : e.severity === "WARNING" ? "warning" : "neutral"}>
                {e.severity === "CRITICAL" ? "Critical" : e.severity === "WARNING" ? "Warning" : "Info"}
              </StatusBadge>
              <span>{EVENT_LABELS[e.eventType] ?? e.eventType}</span>
              {eventDetail(e, users) && <span className="posture-panel__muted">{eventDetail(e, users)}</span>}
              <span className="posture-panel__muted activity-list__time">{new Date(e.occurredAt).toLocaleString()}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Shows the device's unique IDs — useful for support and for correlating with agent logs. */
function DeviceIdPanel({ device }: { device: DeviceSummary }) {
  return (
    <div className="posture-panel device-id-panel">
      <div className="posture-panel__head">
        <strong>Device identifiers</strong>
        <span className="posture-panel__muted">Use these to identify this device in logs, support tickets or the agent --status output</span>
      </div>
      <dl className="posture-grid posture-grid--wide">
        <div className="posture-grid__item">
          <dt>Device ID (platform record, immutable)</dt>
          <dd><code className="device-id-code">{device.id}</code></dd>
        </div>
        {device.identity && (
          <>
            <div className="posture-grid__item">
              <dt>Agent installation ID</dt>
              <dd><code className="device-id-code">{device.identity.agentInstanceId}</code></dd>
            </div>
            <div className="posture-grid__item">
              <dt>Device key</dt>
              <dd>
                {device.identity.keyAlgorithm ?? "—"}
                {device.identity.keyAssuranceLevel ? ` · ${device.identity.keyAssuranceLevel.toLowerCase()}` : ""}
              </dd>
            </div>
            <div className="posture-grid__item">
              <dt>Hardware fingerprint{device.identity.fingerprintVersion != null ? ` (v${device.identity.fingerprintVersion}, SHA-256)` : ""}</dt>
              <dd><code className="device-id-code">{device.identity.fingerprintHash ?? "—"}</code></dd>
            </div>
            <div className="posture-grid__item">
              <dt>Manufacturer / model</dt>
              <dd>{[device.identity.manufacturer, device.identity.model].filter(Boolean).join(" ") || "—"}</dd>
            </div>
          </>
        )}
        <div className="posture-grid__item">
          <dt>User ID</dt>
          <dd><code className="device-id-code">{device.userId}</code></dd>
        </div>
        <div className="posture-grid__item">
          <dt>Hostname</dt>
          <dd>{device.hostname ?? "—"}</dd>
        </div>
        <div className="posture-grid__item">
          <dt>Platform</dt>
          <dd>{device.platform}</dd>
        </div>
        <div className="posture-grid__item">
          <dt>Agent version</dt>
          <dd>{device.agentVersion ?? "—"}</dd>
        </div>
        <div className="posture-grid__item">
          <dt>Enrolled on</dt>
          <dd>{new Date(device.createdAt).toLocaleString()}</dd>
        </div>
      </dl>
    </div>
  );
}

function PosturePanel({ device }: { device: DeviceSummary }) {
  const s: PostureSignals | null = device.postureSignals;
  if (!s || !device.postureEvaluatedAt) {
    return (
      <div className="posture-panel">
        <p className="posture-panel__empty">
          No posture report yet. The agent sends its first one shortly after it starts, then again every 15 minutes.
        </p>
      </div>
    );
  }
  const reported = s.collectedAt ? new Date(s.collectedAt * 1000) : new Date(device.postureEvaluatedAt);
  return (
    <div className="posture-panel">
      <div className="posture-panel__head">
        <StatusBadge tone={device.postureStatus === "COMPLIANT" ? "success" : device.postureStatus === "NON_COMPLIANT" ? "danger" : "neutral"}>
          {device.postureStatus === "COMPLIANT" ? "Compliant" : device.postureStatus === "NON_COMPLIANT" ? "Non-compliant" : "Not fully determined"}
        </StatusBadge>
        <span>Risk score {device.postureRiskScore ?? "—"}/100</span>
        <span className="posture-panel__muted">Checked {reported.toLocaleString()}</span>
      </div>
      {device.postureReasons.length > 0 && (
        <ul className="posture-panel__reasons">
          {device.postureReasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      )}
      <dl className="posture-grid">
        <Check label="Disk encryption (BitLocker)" value={s.diskEncryption} required />
        <Check label="Antivirus real-time protection" value={s.antivirus} required detail={s.antivirusProduct} />
        <Check label="Firewall (all profiles)" value={s.firewall} required />
        <Check label="TPM present" value={s.tpmPresent} />
        <Check label="Secure Boot" value={s.secureBoot} />
        <Fact label="Operating system" value={[s.osName, s.osVersion].filter(Boolean).join(" ")} />
        <Fact label="Most recent update installed" value={s.lastHotfixDate} />
      </dl>
      <p className="posture-panel__muted">
        Required checks decide compliance. The others are shown for information. This is currently report-only: a
        non-compliant device is flagged here but is not blocked.
      </p>
    </div>
  );
}

function Check({ label, value, required, detail }: { label: string; value?: string | null; required?: boolean; detail?: string | null }) {
  const v = (value ?? "").toUpperCase();
  const tone = v === "ENABLED" ? "success" : v === "DISABLED" ? "danger" : "neutral";
  const text = v === "ENABLED" ? "On" : v === "DISABLED" ? "Off" : "Unknown";
  return (
    <div className="posture-grid__item">
      <dt>
        {label}
        {required && <span className="posture-grid__required"> · required</span>}
      </dt>
      <dd>
        <StatusBadge tone={tone}>{text}</StatusBadge>
        {detail && <span className="posture-panel__muted"> {detail}</span>}
      </dd>
    </div>
  );
}

function Fact({ label, value }: { label: string; value?: string | null }) {
  return (
    <div className="posture-grid__item">
      <dt>{label}</dt>
      <dd>{value || "Unknown"}</dd>
    </div>
  );
}

/** Asks the admin how long, and why. Both are required: this lets a laptop that fails security checks reach protected apps. */
function ComplianceExceptionDialog({ device, busy, onCancel, onGrant }: {
  device: DeviceSummary; busy: boolean; onCancel: () => void; onGrant: (days: number, reason: string) => void;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [days, setDays] = useState(7);
  const [reason, setReason] = useState("");
  useEffect(() => { dialogRef.current?.showModal(); }, []);
  const ready = reason.trim().length > 0 && !busy;

  return (
    <dialog ref={dialogRef} className="guide-modal" onClose={onCancel}>
      <div className="guide-modal__header">
        <h2>Allow {deviceLabel(device)} despite failed security checks</h2>
        <button type="button" className="guide-modal__close" onClick={onCancel}>✕</button>
      </div>
      <form
        onSubmit={(e) => { e.preventDefault(); if (ready) onGrant(days, reason.trim()); }}
        className="guide-modal__body"
      >
        <p className="guide-note">
          While this lasts, this laptop can open apps that require a trusted device, even if BitLocker, the firewall or
          antivirus checks fail. It must still be approved, belong to the signed-in user, and be running the agent.
          Every use is recorded. It ends by itself on the date below.
        </p>
        <label className="login-form__field">
          <span>How long</span>
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
            <option value={1}>1 day</option>
            <option value={7}>7 days</option>
            <option value={30}>30 days (maximum)</option>
          </select>
        </label>
        <label className="login-form__field">
          <span>Reason (required, saved with the device)</span>
          <textarea
            value={reason}
            maxLength={500}
            rows={3}
            placeholder="For example: BitLocker rollout for this team is next week"
            onChange={(e) => setReason(e.target.value)}
          />
        </label>
        <div className="guide-modal__footer" style={{ padding: 0, border: 0 }}>
          <button type="button" className="btn-secondary" onClick={onCancel}>Cancel</button>
          <button type="submit" disabled={!ready}>
            <PendingLabel pending={busy} idle="Allow this laptop" busy="Saving…" />
          </button>
        </div>
      </form>
    </dialog>
  );
}

function InstallGuideModal({ onClose }: { onClose: () => void }) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  useEffect(() => { dialogRef.current?.showModal(); }, []);

  function CopyBtn({ text }: { text: string }) {
    const [copied, setCopied] = useState(false);
    return (
      <button
        type="button"
        className="guide-copy-btn"
        onClick={() => { void navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); }); }}
      >
        {copied ? "✓ Copied" : "Copy"}
      </button>
    );
  }

  const uninstallCmd = `$prod = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | Where-Object { $_.DisplayName -eq 'IAM Endpoint Agent' }).PSChildName; Start-Process msiexec.exe -ArgumentList "/x $prod /qn /norestart" -Wait`;
  const statusCmd = `& "C:\\Program Files\\IamEndpointAgent\\iam-endpoint-agent.exe" --status`;

  return (
    <dialog ref={dialogRef} className="guide-modal" onClose={onClose}>
      <div className="guide-modal__header">
        <h2>Agent Install &amp; Uninstall Guide</h2>
        <button type="button" className="guide-modal__close" onClick={onClose}>✕</button>
      </div>
      <div className="guide-modal__body">

        <section className="guide-section">
          <h3>📥 Install (fresh device)</h3>
          <ol className="guide-steps">
            <li>Get the <code>IamEndpointAgent-&lt;version&gt;.msi</code> installer from your IT administrator</li>
            <li>Double-click the <code>.msi</code> file → Next → Install → Finish</li>
            <li>Open <strong>Start Menu</strong> → search <strong>"Enroll Device"</strong> → click it</li>
            <li>Come back here → <strong>Approve</strong> the new device</li>
          </ol>
        </section>

        <section className="guide-section">
          <h3>🗑️ Uninstall</h3>
          <p className="guide-note"><strong>Option 1 — Easiest (Windows Settings):</strong></p>
          <ol className="guide-steps">
            <li>Press <kbd>Windows + I</kbd> → Settings</li>
            <li>Apps → Installed apps</li>
            <li>Search <strong>"IAM"</strong></li>
            <li>Click ⋯ next to <strong>IAM Endpoint Agent</strong> → Uninstall</li>
          </ol>
          <p className="guide-note"><strong>Option 2 — PowerShell (Admin):</strong></p>
          <div className="guide-code-row">
            <code className="guide-code">{uninstallCmd}</code>
            <CopyBtn text={uninstallCmd} />
          </div>
        </section>

        <section className="guide-section">
          <h3>🔄 Re-register (after uninstall)</h3>
          <ol className="guide-steps">
            <li>Click <strong>Delete</strong> on the old device entry above (so it can re-enroll fresh)</li>
            <li>Reinstall the MSI</li>
            <li>Run <strong>Enroll Device</strong> shortcut from Start Menu</li>
            <li>Approve the new pending device here</li>
          </ol>
        </section>

        <section className="guide-section">
          <h3>✅ Check agent status (on the laptop)</h3>
          <div className="guide-code-row">
            <code className="guide-code">{statusCmd}</code>
            <CopyBtn text={statusCmd} />
          </div>
        </section>

        <section className="guide-section">
          <h3>▶️ Start / Stop agent</h3>
          <div className="guide-code-row">
            <code className="guide-code">Start-Service IamEndpointAgent</code>
            <CopyBtn text="Start-Service IamEndpointAgent" />
          </div>
          <div className="guide-code-row" style={{ marginTop: 6 }}>
            <code className="guide-code">Stop-Service IamEndpointAgent</code>
            <CopyBtn text="Stop-Service IamEndpointAgent" />
          </div>
        </section>

      </div>
      <div className="guide-modal__footer">
        <button type="button" className="btn-secondary" onClick={onClose}>Close</button>
      </div>
    </dialog>
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
