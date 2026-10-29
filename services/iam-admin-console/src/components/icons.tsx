import type { ReactNode } from "react";

/** Small inline icon set (24px grid, stroke-based) so the console needs no icon dependency. */
const PATHS: Record<string, ReactNode> = {
  dashboard: (
    <>
      <rect x="3" y="3" width="7" height="9" rx="1.5" />
      <rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" />
      <rect x="3" y="16" width="7" height="5" rx="1.5" />
    </>
  ),
  apps: (
    <>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </>
  ),
  shield: <path d="M12 3l8 3v6c0 4.5-3.2 8.2-8 9-4.8-.8-8-4.5-8-9V6l8-3z M9 12l2 2 4-4" />,
  users: (
    <>
      <circle cx="9" cy="8" r="3.5" />
      <path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6" />
      <path d="M16 4.6a3.5 3.5 0 010 6.8M18 14.3c2.2.7 3.5 2.6 3.5 5.7" />
    </>
  ),
  groups: (
    <>
      <circle cx="12" cy="7" r="3" />
      <circle cx="5.5" cy="16" r="2.5" />
      <circle cx="18.5" cy="16" r="2.5" />
      <path d="M12 10v3M12 13l-5 1.5M12 13l5 1.5" />
    </>
  ),
  switch: (
    <>
      <path d="M4 8h13M13 4l4 4-4 4" />
      <path d="M20 16H7M11 12l-4 4 4 4" />
    </>
  ),
  plug: (
    <>
      <path d="M9 3v5M15 3v5" />
      <path d="M6 8h12v3a6 6 0 01-12 0V8z" />
      <path d="M12 17v4" />
    </>
  ),
  lock: (
    <>
      <rect x="4" y="10" width="16" height="11" rx="2" />
      <path d="M8 10V7a4 4 0 018 0v3" />
    </>
  ),
  cloud: <path d="M7 18a4.5 4.5 0 01-.6-8.96A6 6 0 0118 10.5 3.75 3.75 0 0117.25 18H7z" />,
  palette: (
    <>
      <path d="M12 3a9 9 0 100 18c1.4 0 2-.9 2-1.8 0-1.4-1.2-1.6-1.2-2.7 0-.9.7-1.5 1.7-1.5H17a4 4 0 004-4c0-4-4-8-9-8z" />
      <circle cx="7.5" cy="11" r="1" />
      <circle cx="11" cy="7" r="1" />
      <circle cx="15.5" cy="8" r="1" />
    </>
  ),
  arrow: <path d="M5 12h14M13 6l6 6-6 6" />,
};

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className="icon"
    >
      {PATHS[name]}
    </svg>
  );
}
