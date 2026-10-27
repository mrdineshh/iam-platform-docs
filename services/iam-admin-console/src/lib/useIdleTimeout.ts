import { useEffect } from "react";

const ACTIVITY_EVENTS = ["mousedown", "mousemove", "keydown", "scroll", "wheel", "touchstart"] as const;

/**
 * Calls `onIdle` once after `idleMs` with no user activity in this tab. Any
 * click, key press, scroll or touch restarts the countdown. Activity is
 * sampled at most once a second so a busy mouse doesn't churn timers.
 */
export function useIdleTimeout(onIdle: () => void, idleMs: number): void {
  useEffect(() => {
    let timer = window.setTimeout(onIdle, idleMs);
    let lastReset = Date.now();

    const reset = () => {
      const now = Date.now();
      if (now - lastReset < 1000) return;
      lastReset = now;
      window.clearTimeout(timer);
      timer = window.setTimeout(onIdle, idleMs);
    };

    ACTIVITY_EVENTS.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    return () => {
      window.clearTimeout(timer);
      ACTIVITY_EVENTS.forEach((e) => window.removeEventListener(e, reset));
    };
  }, [onIdle, idleMs]);
}
