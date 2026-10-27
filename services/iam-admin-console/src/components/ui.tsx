import type { ReactNode } from "react";
import { Link } from "react-router-dom";

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div className="page-header__text">
        <h1>{title}</h1>
        {subtitle && <p className="page-header__subtitle">{subtitle}</p>}
      </div>
      {actions && <div className="page-header__actions">{actions}</div>}
    </header>
  );
}

export function Alert({ kind = "error", children }: { kind?: "error" | "success" | "info"; children: ReactNode }) {
  return (
    <div role={kind === "error" ? "alert" : "status"} className={`alert alert--${kind}`}>
      {children}
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="spinner-wrap">
      <span className="spinner" aria-hidden="true" />
      {label && <span>{label}</span>}
    </span>
  );
}

/** Button that shows an inline spinner + pending label while an action is in flight. */
export function PendingLabel({ pending, idle, busy }: { pending: boolean; idle: string; busy: string }) {
  return pending ? (
    <>
      <span className="spinner spinner--inline" aria-hidden="true" />
      {busy}
    </>
  ) : (
    <>{idle}</>
  );
}

export function SkeletonRows({ rows = 4 }: { rows?: number }) {
  return (
    <div className="card skeleton-table" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="skeleton skeleton--row" />
      ))}
    </div>
  );
}

export function SkeletonTiles({ count = 4 }: { count?: number }) {
  return (
    <div className="app-tiles" aria-busy="true" aria-label="Loading">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="skeleton skeleton--tile" />
      ))}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <div className="empty-state__icon" aria-hidden="true">
        ∅
      </div>
      <h3>{title}</h3>
      {description && <p>{description}</p>}
      {action}
    </div>
  );
}

type BadgeTone = "success" | "warning" | "danger" | "neutral" | "info";

export function StatusBadge({ tone, children }: { tone: BadgeTone; children: ReactNode }) {
  return <span className={`badge badge--${tone}`}>{children}</span>;
}

export function StatCard({
  label,
  value,
  hint,
  to,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  to?: string;
}) {
  const body = (
    <>
      <span className="stat-card__label">{label}</span>
      <span className="stat-card__value">{value}</span>
      {hint && <span className="stat-card__hint">{hint}</span>}
    </>
  );
  return to ? (
    <Link className="stat-card stat-card--link" to={to}>
      {body}
    </Link>
  ) : (
    <div className="stat-card">{body}</div>
  );
}

export function Avatar({ name }: { name: string }) {
  return (
    <span className="avatar" aria-hidden="true">
      {name.charAt(0).toUpperCase()}
    </span>
  );
}

// Logos for known apps, matched by name (case-insensitive). Anything else
// falls back to the first-letter badge, so newly connected apps still render.
const APP_LOGOS: Array<{ match: string; src: string; chip: boolean }> = [
  { match: "pulse", src: "/app-logos/pulse.svg", chip: false },
  { match: "google", src: "/app-logos/google.png", chip: true },
];

export function AppIcon({ name, size = 52 }: { name: string; size?: number }) {
  const logo = APP_LOGOS.find((l) => name.toLowerCase().includes(l.match));
  const style = { width: size, height: size, fontSize: size * 0.45 };
  if (!logo) {
    return (
      <span className="app-icon app-icon--letter" style={style} aria-hidden="true">
        {name.charAt(0).toUpperCase()}
      </span>
    );
  }
  return (
    <span className={logo.chip ? "app-icon app-icon--chip" : "app-icon"} style={style} aria-hidden="true">
      <img src={logo.src} alt="" width={size} height={size} />
    </span>
  );
}
