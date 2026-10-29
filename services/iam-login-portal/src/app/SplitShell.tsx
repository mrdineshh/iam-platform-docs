import type { CSSProperties, ReactNode } from "react";
import { IntegrationGrid } from "./IntegrationGrid";
import { SecurityBackdrop } from "./SecurityBackdrop";

/**
 * Sign-in page frame: the connected-apps orbit on the left, the form on the right, over one
 * continuous dark canvas with an interactive security mesh behind both. The tenant's brand
 * color arrives via `style` (CSS custom properties) and still applies to buttons and links.
 */
export function SplitShell({ style, children }: { style?: CSSProperties; children: ReactNode }) {
  return (
    <main className="login-split" style={style}>
      <SecurityBackdrop />
      <aside className="login-split__art" aria-hidden="true">
        <IntegrationGrid />
      </aside>
      <section className="login-page login-split__panel">{children}</section>
    </main>
  );
}
