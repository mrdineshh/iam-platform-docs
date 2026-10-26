import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { loadSession } from "@/lib/session";
import { Shell } from "@/components/Shell";

/**
 * Like ProtectedRoute, but allows any authenticated session -- ADMIN or
 * USER. ProtectedRoute is ADMIN-only, which is wrong for pages like "My
 * Security" that every user, not just admins, needs (self-service 2FA
 * enrollment). Server-side, /api/v1/me/2fa/* is gated the same way
 * (AdminAccessGuard.requireValidSession, not requireTenantAdmin) -- this is
 * just the matching client-side UX convenience, same disclaimer as
 * ProtectedRoute's own comment.
 */
export function SessionRoute({ children }: { children: ReactNode }) {
  const session = loadSession();
  if (!session) return <Navigate to="/login" replace />;
  return <Shell>{children}</Shell>;
}
