// Session token held in sessionStorage (cleared on tab close) -- inherent
// to the "React+Vite static SPA" tech choice (no server to set an httpOnly
// cookie from). A real XSS vulnerability anywhere in this app could read
// this. Flagged, not fixed -- see docs/specs/iam-admin-console-SPEC.md
// Section 6.

export interface AdminSession {
  token: string;
  role: string;
  tenantId: string;
  tenantName: string;
  email?: string;
  displayName?: string;
}

const KEY = "iam-admin-console:session";
// Stashes the admin's own session while "Switch to user" is active, so
// "Switch back" can restore it exactly -- without this, switching to a user
// would be a one-way door (the admin would have to log out and back in).
const IMPERSONATION_ORIGINAL_KEY = "iam-admin-console:impersonation-original";

export function saveSession(session: AdminSession): void {
  sessionStorage.setItem(KEY, JSON.stringify(session));
}

export function loadSession(): AdminSession | null {
  const raw = sessionStorage.getItem(KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as AdminSession;
  } catch {
    return null;
  }
}

export function clearSession(): void {
  sessionStorage.removeItem(KEY);
  sessionStorage.removeItem(IMPERSONATION_ORIGINAL_KEY);
}

export function isAdmin(session: AdminSession | null): boolean {
  return session?.role === "ADMIN";
}

/** Stashes the current (real admin) session, then makes `targetSession` the active one. */
export function startImpersonation(targetSession: AdminSession): void {
  const current = loadSession();
  if (current) {
    sessionStorage.setItem(IMPERSONATION_ORIGINAL_KEY, JSON.stringify(current));
  }
  saveSession(targetSession);
}

export function isImpersonating(): boolean {
  return sessionStorage.getItem(IMPERSONATION_ORIGINAL_KEY) !== null;
}

/** Restores the stashed admin session. No-op (returns false) if nothing was stashed. */
export function endImpersonation(): boolean {
  const raw = sessionStorage.getItem(IMPERSONATION_ORIGINAL_KEY);
  if (!raw) return false;
  sessionStorage.removeItem(IMPERSONATION_ORIGINAL_KEY);
  sessionStorage.setItem(KEY, raw);
  return true;
}
