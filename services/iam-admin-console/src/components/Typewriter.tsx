import { useEffect, useState } from "react";

const reducedMotion = () =>
  typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

/**
 * Types `lines` out one after another, like someone writing them: the first
 * line completes before the second starts, and a caret follows whichever line
 * is being typed (it keeps blinking on the last one). The full text is also
 * rendered invisibly underneath, so the block never changes size or jumps
 * while it types. With "reduce motion" on, the text simply appears.
 */
export function Typewriter({
  lines,
  charMs = 55,
  pauseMs = 450,
  startDelayMs = 600,
}: {
  lines: string[];
  charMs?: number;
  pauseMs?: number;
  startDelayMs?: number;
}) {
  const [typed, setTyped] = useState<number[]>(() => (reducedMotion() ? lines.map((l) => l.length) : lines.map(() => 0)));
  const [active, setActive] = useState(() => (reducedMotion() ? lines.length - 1 : 0));

  useEffect(() => {
    if (reducedMotion()) return;
    setTyped(lines.map(() => 0));
    setActive(0);

    let line = 0;
    let chars = 0;
    let timer: number;

    const tick = () => {
      chars += 1;
      setTyped((prev) => prev.map((n, i) => (i === line ? chars : n)));
      if (chars < lines[line].length) {
        timer = window.setTimeout(tick, charMs);
      } else if (line < lines.length - 1) {
        line += 1;
        chars = 0;
        timer = window.setTimeout(() => {
          setActive(line);
          tick();
        }, pauseMs);
      }
    };

    timer = window.setTimeout(tick, startDelayMs);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <>
      {lines.map((text, i) => (
        <span key={i} className={`tw tw--${i}`} aria-label={text}>
          <span className="tw__ghost" aria-hidden="true">
            {text}
          </span>
          <span className="tw__live" aria-hidden="true">
            {text.slice(0, typed[i] ?? 0)}
            {i === active && <span className="tw__caret" />}
          </span>
        </span>
      ))}
    </>
  );
}
