import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { isAdmin, loadSession } from "@/lib/session";
import { Shell } from "@/components/Shell";

/**
 * Client-side gate only -- purely a UX convenience (redirect to /login
 * instead of showing a broken page). The real gate is every backend
 * endpoint's own AdminAccessGuard check (see
 * docs/specs/iam-admin-console-SPEC.md Section 0): a non-admin who bypasses
 * this component entirely (e.g. via devtools) still gets 403'd server-side
 * on every actual data call.
 */
export function ProtectedRoute({ children }: { children: ReactNode }) {
  const session = loadSession();
  if (!session) return <Navigate to="/login" replace />;
  if (!isAdmin(session)) return <Navigate to="/login" replace />;
  return <Shell>{children}</Shell>;
}
