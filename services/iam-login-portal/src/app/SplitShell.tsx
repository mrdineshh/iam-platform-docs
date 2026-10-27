import type { CSSProperties, ReactNode } from "react";
import { Typewriter } from "./Typewriter";

/**
 * Sign-in page frame: artwork and a typed tagline on the left, the form on the
 * right, over one continuous dark canvas. The tenant's brand color arrives via
 * `style` (CSS custom properties) and still applies to buttons and links.
 */
export function SplitShell({ style, children }: { style?: CSSProperties; children: ReactNode }) {
  return (
    <main className="login-split" style={style}>
      <aside className="login-split__art" aria-hidden="true">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src="/login-art.jpg" alt="" />
        <div className="login-split__caption">
          <Typewriter lines={["One sign-in. Every app.", "Secure by policy, on every request."]} />
        </div>
      </aside>
      <section className="login-page login-split__panel">{children}</section>
    </main>
  );
}
