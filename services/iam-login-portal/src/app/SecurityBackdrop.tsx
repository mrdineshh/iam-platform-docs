"use client";

import { useEffect, useRef } from "react";

/**
 * Interactive security-network backdrop for the sign-in page.
 *
 * A mesh of drifting nodes with small data packets travelling the links. Moving the mouse sweeps
 * a "scanner" over the mesh: nearby nodes are verified (they turn green and link to the cursor),
 * a few "guard" nodes show a shield that lights up, and clicking sends out a radar ring. Purely
 * decorative: it sits behind the page, ignores pointer events, and is static for people who
 * prefer reduced motion.
 */
interface Node {
  x: number;
  y: number;
  vx: number;
  vy: number;
  guard: boolean;
  lit: number; // 0..1, eases toward 1 while the cursor is near
}

interface Packet {
  a: number;
  b: number;
  t: number;
  speed: number;
}

interface Ring {
  x: number;
  y: number;
  age: number;
}

const LINK = 150;
const SCAN = 190;

export function SecurityBackdrop() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;

    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
    let w = 0;
    let h = 0;
    let nodes: Node[] = [];
    const packets: Packet[] = [];
    const rings: Ring[] = [];
    const mouse = { x: -9999, y: -9999, active: false };
    let raf = 0;

    function resize() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas!.clientWidth;
      h = canvas!.clientHeight;
      canvas!.width = w * dpr;
      canvas!.height = h * dpr;
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
      const count = Math.max(30, Math.min(95, Math.round((w * h) / 17000)));
      nodes = Array.from({ length: count }, (_, i) => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.32,
        vy: (Math.random() - 0.5) * 0.32,
        guard: i % 9 === 0,
        lit: 0,
      }));
    }

    function shield(x: number, y: number, s: number, color: string) {
      ctx!.beginPath();
      ctx!.moveTo(x, y - s);
      ctx!.lineTo(x + s * 0.85, y - s * 0.6);
      ctx!.lineTo(x + s * 0.85, y + s * 0.1);
      ctx!.quadraticCurveTo(x + s * 0.7, y + s * 0.8, x, y + s * 1.1);
      ctx!.quadraticCurveTo(x - s * 0.7, y + s * 0.8, x - s * 0.85, y + s * 0.1);
      ctx!.lineTo(x - s * 0.85, y - s * 0.6);
      ctx!.closePath();
      ctx!.strokeStyle = color;
      ctx!.lineWidth = 1.4;
      ctx!.stroke();
      ctx!.beginPath();
      ctx!.moveTo(x - s * 0.35, y + s * 0.05);
      ctx!.lineTo(x - s * 0.05, y + s * 0.38);
      ctx!.lineTo(x + s * 0.42, y - s * 0.28);
      ctx!.stroke();
    }

    function frame() {
      ctx!.clearRect(0, 0, w, h);

      // Cursor scanner glow.
      if (mouse.active) {
        const g = ctx!.createRadialGradient(mouse.x, mouse.y, 0, mouse.x, mouse.y, SCAN);
        g.addColorStop(0, "rgba(94,234,212,0.16)");
        g.addColorStop(1, "rgba(94,234,212,0)");
        ctx!.fillStyle = g;
        ctx!.beginPath();
        ctx!.arc(mouse.x, mouse.y, SCAN, 0, Math.PI * 2);
        ctx!.fill();
      }

      for (const n of nodes) {
        if (!reduce) {
          n.x += n.vx;
          n.y += n.vy;
          if (n.x < -10 || n.x > w + 10) n.vx *= -1;
          if (n.y < -10 || n.y > h + 10) n.vy *= -1;
        }
        const d = mouse.active ? Math.hypot(n.x - mouse.x, n.y - mouse.y) : Infinity;
        const target = d < SCAN ? 1 - d / SCAN : 0;
        n.lit += (target - n.lit) * 0.12;
        if (d < SCAN && d > 1 && !reduce) {
          // A gentle pull toward the scanner, so the mesh visibly reacts to the pointer.
          n.x += ((mouse.x - n.x) / d) * 0.35 * target;
          n.y += ((mouse.y - n.y) / d) * 0.35 * target;
        }
      }

      // Links between nodes.
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i];
          const b = nodes[j];
          const dist = Math.hypot(a.x - b.x, a.y - b.y);
          if (dist > LINK) continue;
          const lit = Math.max(a.lit, b.lit);
          const alpha = (1 - dist / LINK) * (0.22 + lit * 0.6);
          ctx!.strokeStyle = lit > 0.15 ? `rgba(74,222,128,${alpha})` : `rgba(94,234,212,${alpha})`;
          ctx!.lineWidth = 0.6 + lit * 1.1;
          ctx!.beginPath();
          ctx!.moveTo(a.x, a.y);
          ctx!.lineTo(b.x, b.y);
          ctx!.stroke();
        }
      }

      // Cursor links to nearby nodes.
      if (mouse.active) {
        for (const n of nodes) {
          const d = Math.hypot(n.x - mouse.x, n.y - mouse.y);
          if (d > SCAN) continue;
          ctx!.strokeStyle = `rgba(165,180,252,${(1 - d / SCAN) * 0.7})`;
          ctx!.lineWidth = 1;
          ctx!.beginPath();
          ctx!.moveTo(mouse.x, mouse.y);
          ctx!.lineTo(n.x, n.y);
          ctx!.stroke();
        }
      }

      // Data packets travelling along links.
      if (!reduce) {
        if (packets.length < 14 && Math.random() < 0.06) {
          const a = Math.floor(Math.random() * nodes.length);
          const near = nodes
            .map((n, idx) => ({ idx, d: Math.hypot(n.x - nodes[a].x, n.y - nodes[a].y) }))
            .filter((o) => o.idx !== a && o.d < LINK);
          if (near.length) packets.push({ a, b: near[Math.floor(Math.random() * near.length)].idx, t: 0, speed: 0.012 + Math.random() * 0.012 });
        }
        for (let i = packets.length - 1; i >= 0; i--) {
          const p = packets[i];
          p.t += p.speed;
          const a = nodes[p.a];
          const b = nodes[p.b];
          if (p.t >= 1 || Math.hypot(a.x - b.x, a.y - b.y) > LINK) {
            packets.splice(i, 1);
            continue;
          }
          ctx!.fillStyle = "rgba(255,255,255,0.9)";
          ctx!.shadowColor = "#5eead4";
          ctx!.shadowBlur = 10;
          ctx!.beginPath();
          ctx!.arc(a.x + (b.x - a.x) * p.t, a.y + (b.y - a.y) * p.t, 2, 0, Math.PI * 2);
          ctx!.fill();
          ctx!.shadowBlur = 0;
        }
      }

      // Nodes and guard shields.
      for (const n of nodes) {
        const color = n.lit > 0.15 ? "74,222,128" : "94,234,212";
        if (n.guard) {
          shield(n.x, n.y, 7 + n.lit * 5, `rgba(${color},${0.45 + n.lit * 0.55})`);
        } else {
          ctx!.fillStyle = `rgba(${color},${0.4 + n.lit * 0.6})`;
          ctx!.beginPath();
          ctx!.arc(n.x, n.y, 1.8 + n.lit * 2.2, 0, Math.PI * 2);
          ctx!.fill();
        }
      }

      // Click radar rings.
      for (let i = rings.length - 1; i >= 0; i--) {
        const r = rings[i];
        r.age += 1;
        const life = r.age / 70;
        if (life >= 1) {
          rings.splice(i, 1);
          continue;
        }
        ctx!.strokeStyle = `rgba(94,234,212,${0.6 * (1 - life)})`;
        ctx!.lineWidth = 2;
        ctx!.beginPath();
        ctx!.arc(r.x, r.y, life * 260, 0, Math.PI * 2);
        ctx!.stroke();
      }

      if (!reduce) raf = requestAnimationFrame(frame);
    }

    function onMove(e: MouseEvent) {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
      mouse.active = true;
      if (reduce) frame();
    }
    const onLeave = () => {
      mouse.active = false;
      if (reduce) frame();
    };
    const onClick = (e: MouseEvent) => {
      rings.push({ x: e.clientX, y: e.clientY, age: 0 });
    };

    resize();
    frame();
    window.addEventListener("resize", resize);
    window.addEventListener("mousemove", onMove);
    window.addEventListener("click", onClick);
    document.addEventListener("mouseleave", onLeave);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("click", onClick);
      document.removeEventListener("mouseleave", onLeave);
    };
  }, []);

  return <canvas ref={ref} className="sec-backdrop" aria-hidden="true" />;
}
