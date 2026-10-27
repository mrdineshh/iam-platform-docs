"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { filterApps, knownLogo, tileColor, type LaunchApp } from "@/lib/launchpad";
import { signOutAction } from "./actions";

/**
 * The page people land on after signing in: every app they may open, as a grid
 * of tiles, with search and a sign-out menu. Light, spacious and quiet on
 * purpose, in the style of a standard app launcher. Tiles open in a new tab.
 */
export function Launchpad({
  tenantName,
  logoUrl,
  apps,
  tenantOverride,
}: {
  tenantName: string;
  logoUrl: string | null;
  apps: LaunchApp[];
  tenantOverride: string | null;
}) {
  const [query, setQuery] = useState("");
  const visible = useMemo(() => filterApps(apps, query), [apps, query]);
  const menuRef = useRef<HTMLDetailsElement>(null);

  // Close the account menu on an outside click or Escape.
  useEffect(() => {
    function close(e: Event) {
      const menu = menuRef.current;
      if (!menu?.open) return;
      if (e.type === "keydown" && (e as KeyboardEvent).key !== "Escape") return;
      if (e.type === "mousedown" && menu.contains(e.target as Node)) return;
      menu.open = false;
    }
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", close);
    };
  }, []);

  return (
    <div className="lp">
      <header className="lp__bar">
        <div className="lp__brand">
          {logoUrl ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img src={logoUrl} alt={tenantName} className="lp__logo" />
          ) : (
            <>
              <span className="lp__mark" aria-hidden="true">
                {tenantName.charAt(0).toUpperCase()}
              </span>
              <strong>{tenantName}</strong>
            </>
          )}
          <span className="lp__brand-sub">Apps</span>
        </div>

        <label className="lp__search">
          <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true" focusable="false">
            <path
              fill="currentColor"
              d="M15.5 14h-.79l-.28-.27A6.47 6.47 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14"
            />
          </svg>
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search your apps"
            aria-label="Search your apps"
            autoComplete="off"
          />
        </label>

        <details className="lp__menu" ref={menuRef}>
          <summary className="lp__avatar" aria-label="Account menu">
            <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" focusable="false">
              <path
                fill="currentColor"
                d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8m0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4"
              />
            </svg>
          </summary>
          <div className="lp__menu-panel">
            <p className="lp__menu-tenant">Signed in to {tenantName}</p>
            <form action={signOutAction.bind(null, tenantOverride)}>
              <button type="submit" className="lp__signout">
                Sign out
              </button>
            </form>
          </div>
        </details>
      </header>

      <main className="lp__main">
        <h1>Your apps</h1>
        <p className="lp__count">
          {apps.length === 0
            ? "Nothing here yet"
            : query.trim()
              ? `${visible.length} of ${apps.length} apps`
              : `${apps.length} app${apps.length === 1 ? "" : "s"} available`}
        </p>

        {apps.length === 0 ? (
          <div className="lp__empty">
            <h2>No apps yet</h2>
            <p>Your administrator hasn&rsquo;t given you access to any apps. Check back soon, or ask them to add you to a group.</p>
          </div>
        ) : visible.length === 0 ? (
          <div className="lp__empty">
            <h2>No matches</h2>
            <p>No app matches &ldquo;{query.trim()}&rdquo;.</p>
          </div>
        ) : (
          <div className="lp__grid">
            {visible.map((app) => {
              const logo = knownLogo(app.name);
              return (
                <a key={app.id} href={app.launchUrl} target="_blank" rel="noopener noreferrer" className="lp__tile">
                  {logo ? (
                    <span className="lp__icon lp__icon--logo" aria-hidden="true">
                      {/* eslint-disable-next-line @next/next/no-img-element */}
                      <img src={logo} alt="" />
                    </span>
                  ) : (
                    <span className="lp__icon" style={{ background: tileColor(app.name) }} aria-hidden="true">
                      {app.name.charAt(0).toUpperCase()}
                    </span>
                  )}
                  <span className="lp__name">{app.name}</span>
                </a>
              );
            })}
          </div>
        )}
      </main>
    </div>
  );
}
