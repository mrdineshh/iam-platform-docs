import type { ReactNode } from "react";
import { Icon } from "@/components/icons";

/**
 * "Works with the tools you already use" tile grid for the sign-in page. The marks are simple
 * vector wordmarks drawn here (no external image hosting, nothing to load at sign-in time).
 */
const TILES: Array<{ name: string; logo: ReactNode }> = [
  {
    name: "Microsoft",
    logo: (
      <>
        <svg viewBox="0 0 22 22" width="30" height="30" aria-hidden="true">
          <rect x="1" y="1" width="9.5" height="9.5" fill="#f25022" />
          <rect x="11.5" y="1" width="9.5" height="9.5" fill="#7fba00" />
          <rect x="1" y="11.5" width="9.5" height="9.5" fill="#00a4ef" />
          <rect x="11.5" y="11.5" width="9.5" height="9.5" fill="#ffb900" />
        </svg>
        <span className="int-tile__word" style={{ color: "#6b6b6b", fontWeight: 600 }}>Microsoft</span>
      </>
    ),
  },
  {
    name: "Google",
    logo: (
      <span className="int-tile__word int-tile__word--lg" style={{ fontWeight: 500 }}>
        <span style={{ color: "#4285f4" }}>G</span>
        <span style={{ color: "#ea4335" }}>o</span>
        <span style={{ color: "#fbbc05" }}>o</span>
        <span style={{ color: "#4285f4" }}>g</span>
        <span style={{ color: "#34a853" }}>l</span>
        <span style={{ color: "#ea4335" }}>e</span>
      </span>
    ),
  },
  {
    name: "Slack",
    logo: (
      <>
        <svg viewBox="0 0 24 24" width="28" height="28" aria-hidden="true">
          <rect x="3" y="9.5" width="9" height="4" rx="2" fill="#36c5f0" />
          <rect x="12" y="3" width="4" height="9" rx="2" fill="#2eb67d" />
          <rect x="12" y="12" width="9" height="4" rx="2" fill="#ecb22e" />
          <rect x="8" y="12" width="4" height="9" rx="2" fill="#e01e5a" />
        </svg>
        <span className="int-tile__word int-tile__word--lg" style={{ color: "#1d1c1d", fontWeight: 800 }}>slack</span>
      </>
    ),
  },
  {
    name: "Workday",
    logo: (
      <span className="int-tile__stack">
        <svg viewBox="0 0 60 20" width="56" height="18" aria-hidden="true">
          <path d="M6 18a24 24 0 0148 0" fill="none" stroke="#f5a623" strokeWidth="4" strokeLinecap="round" />
        </svg>
        <span className="int-tile__word" style={{ color: "#0875e1", fontWeight: 700, letterSpacing: "0.04em" }}>workday.</span>
      </span>
    ),
  },
  {
    name: "AWS",
    logo: (
      <span className="int-tile__stack">
        <span className="int-tile__word int-tile__word--xl" style={{ color: "#232f3e", fontWeight: 700 }}>aws</span>
        <svg viewBox="0 0 60 12" width="52" height="10" aria-hidden="true">
          <path d="M4 3c14 8 36 8 52 0" fill="none" stroke="#ff9900" strokeWidth="3.5" strokeLinecap="round" />
        </svg>
      </span>
    ),
  },
  {
    name: "Atlassian",
    logo: (
      <span className="int-tile__stack">
        <svg viewBox="0 0 32 28" width="34" height="30" aria-hidden="true">
          <path d="M9 12l-8 14c-.4.7.1 1.6.9 1.6h12.4c.4 0 .8-.2 1-.6C18.100 21.500 15.500 15.500 9 12z" fill="#2684ff" />
          <path d="M15.600 2.300c-.3-.5-1.100-.5-1.400 0-3 5-3.300 10.600-.6 15.400l4.500 8.800c.2.400.6.600 1 .6H30c.8 0 1.300-.9.900-1.600L15.600 2.300z" fill="#0052cc" />
        </svg>
        <span className="int-tile__word" style={{ color: "#0052cc", fontWeight: 800, fontSize: "0.62rem", letterSpacing: "0.06em" }}>ATLASSIAN</span>
      </span>
    ),
  },
  {
    name: "ServiceNow",
    logo: (
      <span className="int-tile__word" style={{ color: "#111", fontWeight: 700, fontSize: "1.05rem" }}>
        servicen<span style={{ color: "#62d84e" }}>o</span>w
      </span>
    ),
  },
  {
    name: "Salesforce",
    logo: (
      <svg viewBox="0 0 80 52" width="92" height="60" aria-hidden="true">
        <path
          d="M33 8c4-4 11-5 16-1 3-2 8-2 11 1 4 4 3 8 1 10 5 1 8 6 7 11-1 5-6 8-11 7-3 4-9 5-14 2-4 4-12 4-16 0-6 2-12-2-12-8 0-3 2-6 4-7-2-5 1-11 7-12 2-3 5-4 7-3z"
          fill="#00a1e0"
        />
        <text x="40" y="31" textAnchor="middle" fontSize="9" fontWeight="700" fill="#fff" fontFamily="system-ui, sans-serif">salesforce</text>
      </svg>
    ),
  },
];

export function IntegrationGrid() {
  const step = 360 / TILES.length;
  return (
    <div className="orbit-wrap">
      <h2 className="orbit-title">Easily integrate with your business technologies</h2>
      <div className="orbit" role="img" aria-label="Apps that connect to the platform">
        <span className="orbit__ring orbit__ring--outer" />
        <span className="orbit__ring orbit__ring--inner" />

        {TILES.map((t, i) => (
          <span key={`spoke-${t.name}`} className="orbit__spoke" style={{ ["--a" as string]: `${i * step}deg` }} />
        ))}
        {TILES.map((t, i) => (
          <div key={t.name} className="orbit__chip" style={{ ["--a" as string]: `${i * step}deg` }} title={t.name}>
            <span className="orbit__chip-in">{t.logo}</span>
          </div>
        ))}

        <div className="orbit__hub">
          <span className="orbit__pulse" />
          <span className="orbit__pulse orbit__pulse--b" />
          <div className="orbit__core">
            <Icon name="shield" size={44} />
            <span>IAM</span>
          </div>
        </div>
      </div>
    </div>
  );
}
