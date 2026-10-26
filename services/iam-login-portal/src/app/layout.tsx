import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Sign in",
};

// Single static, generic theme for every tenant (OQ-4, deliberately
// deferred -- see docs/specs/iam-login-portal-SPEC.md Section 6 and
// BRD FR-6.1). Real per-tenant branding is a follow-up SPEC.
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
